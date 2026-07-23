use std::{io, net::SocketAddr};

use anyhow::{Context, Result, bail};
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

use crate::config::Transport;

#[derive(Debug)]
pub struct ResponseObservation {
    pub response_code: String,
    pub truncated: bool,
    pub authenticated_data: bool,
    pub rrsig_response: bool,
    pub dnssec_records: u64,
}

pub fn build_query(
    id: u16,
    name: &Name,
    record_type: RecordType,
    dnssec: bool,
    edns_payload: u16,
) -> Result<Vec<u8>> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name.clone(), record_type));
    let mut edns = Edns::new();
    edns.set_max_payload(edns_payload).set_dnssec_ok(dnssec);
    message.set_edns(edns);
    message.to_vec().context("failed to encode DNS query")
}

pub fn inspect_response(expected_id: u16, wire: &[u8]) -> Result<ResponseObservation> {
    let message = Message::from_vec(wire).context("malformed DNS response")?;
    if message.metadata.id != expected_id {
        bail!(
            "DNS transaction ID mismatch: expected {expected_id}, received {}",
            message.metadata.id
        );
    }
    if message.metadata.message_type != MessageType::Response {
        bail!("received a DNS query instead of a response");
    }
    let mut dnssec_records = 0_u64;
    let mut rrsig_response = false;
    for record in message.all_sections() {
        let record_type = record.record_type();
        if record_type.is_dnssec() {
            dnssec_records = dnssec_records.saturating_add(1);
        }
        rrsig_response |= record_type == RecordType::RRSIG;
    }
    Ok(ResponseObservation {
        response_code: format!("{:?}", message.metadata.response_code),
        truncated: message.metadata.truncation,
        authenticated_data: message.metadata.authentic_data,
        rrsig_response,
        dnssec_records,
    })
}

pub struct DnsClient {
    transport: Transport,
    target: SocketAddr,
    udp: Option<UdpSocket>,
    tcp: Option<TcpStream>,
}

impl DnsClient {
    pub fn new(transport: Transport, target: SocketAddr) -> Self {
        Self {
            transport,
            target,
            udp: None,
            tcp: None,
        }
    }

    pub fn invalidate(&mut self) {
        self.udp = None;
        self.tcp = None;
    }

    pub async fn exchange(&mut self, query: &[u8]) -> io::Result<Vec<u8>> {
        match self.transport {
            Transport::Udp => self.exchange_udp(query).await,
            Transport::Tcp => self.exchange_tcp(query).await,
        }
    }

    async fn exchange_udp(&mut self, query: &[u8]) -> io::Result<Vec<u8>> {
        if self.udp.is_none() {
            let bind = if self.target.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind).await?;
            socket.connect(self.target).await?;
            self.udp = Some(socket);
        }
        let socket = self.udp.as_ref().expect("UDP socket was initialized");
        socket.send(query).await?;
        let mut buffer = vec![0_u8; 65_535];
        let received = socket.recv(&mut buffer).await?;
        buffer.truncate(received);
        Ok(buffer)
    }

    async fn exchange_tcp(&mut self, query: &[u8]) -> io::Result<Vec<u8>> {
        if self.tcp.is_none() {
            self.tcp = Some(TcpStream::connect(self.target).await?);
        }
        let stream = self.tcp.as_mut().expect("TCP stream was initialized");
        let length = u16::try_from(query.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "DNS query exceeds 65535 bytes")
        })?;
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(query).await?;
        let response_length = stream.read_u16().await? as usize;
        let mut response = vec![0_u8; response_length];
        stream.read_exact(&mut response).await?;
        Ok(response)
    }
}

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::domain::Name;
use hickory_proto::rr::rdata::PTR;
use hickory_proto::rr::{RData, Record, RecordType};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub const TEST_RESOLVERS_ENV: &str = "DNS_CHECK_TEST_RESOLVERS";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedQuery {
    pub name: String,
    pub record_type: RecordType,
}

#[allow(dead_code)]
#[derive(Clone)]
pub enum MockResponse {
    Address(Ipv4Addr),
    NxDomain,
    Ptr(&'static str),
}

pub struct MockResolver {
    socket_addr: SocketAddr,
    queries: Arc<Mutex<Vec<ObservedQuery>>>,
    shutdown: Arc<AtomicBool>,
    udp_thread: Option<JoinHandle<()>>,
    tcp_thread: Option<JoinHandle<()>>,
}

impl MockResolver {
    pub fn spawn(response: MockResponse) -> Self {
        let tcp_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let socket_addr = tcp_listener.local_addr().unwrap();
        let udp_socket = UdpSocket::bind(socket_addr).unwrap();
        let queries = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        udp_socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        tcp_listener.set_nonblocking(true).unwrap();

        let udp_thread = Some(spawn_udp_server(
            udp_socket,
            response.clone(),
            Arc::clone(&queries),
            Arc::clone(&shutdown),
        ));
        let tcp_thread = Some(spawn_tcp_server(
            tcp_listener,
            response,
            Arc::clone(&queries),
            Arc::clone(&shutdown),
        ));

        Self {
            socket_addr,
            queries,
            shutdown,
            udp_thread,
            tcp_thread,
        }
    }

    pub fn socket_addr(&self) -> SocketAddr {
        self.socket_addr
    }

    pub fn queries(&self) -> Vec<ObservedQuery> {
        self.queries.lock().unwrap().clone()
    }
}

impl Drop for MockResolver {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);

        if let Some(handle) = self.udp_thread.take() {
            handle.join().unwrap();
        }

        if let Some(handle) = self.tcp_thread.take() {
            handle.join().unwrap();
        }
    }
}

fn spawn_udp_server(
    socket: UdpSocket,
    response: MockResponse,
    queries: Arc<Mutex<Vec<ObservedQuery>>>,
    shutdown: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0_u8; 512];

        while !shutdown.load(Ordering::Relaxed) {
            match socket.recv_from(&mut buffer) {
                Ok((len, peer_addr)) => {
                    if len == 0 {
                        continue;
                    }

                    let request = Message::from_vec(&buffer[..len]).unwrap();
                    record_query(&queries, &request);
                    let response_bytes = build_response(&request, &response);
                    socket.send_to(&response_bytes, peer_addr).unwrap();
                }
                Err(err)
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(err) => panic!("UDP server error: {err}"),
            }
        }
    })
}

fn spawn_tcp_server(
    listener: TcpListener,
    response: MockResponse,
    queries: Arc<Mutex<Vec<ObservedQuery>>>,
    shutdown: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        while !shutdown.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_millis(100)))
                        .unwrap();

                    let mut len_bytes = [0_u8; 2];
                    if let Err(err) = stream.read_exact(&mut len_bytes) {
                        if err.kind() == std::io::ErrorKind::TimedOut {
                            continue;
                        }
                        panic!("TCP server read failed: {err}");
                    }

                    let length = u16::from_be_bytes(len_bytes) as usize;
                    let mut request_bytes = vec![0_u8; length];
                    stream.read_exact(&mut request_bytes).unwrap();

                    let request = Message::from_vec(&request_bytes).unwrap();
                    record_query(&queries, &request);

                    let response_bytes = build_response(&request, &response);
                    stream
                        .write_all(&(response_bytes.len() as u16).to_be_bytes())
                        .unwrap();
                    stream.write_all(&response_bytes).unwrap();
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(25));
                }
                Err(err) => panic!("TCP accept failed: {err}"),
            }
        }
    })
}

fn record_query(queries: &Arc<Mutex<Vec<ObservedQuery>>>, request: &Message) {
    let query = request.queries().first().unwrap();
    queries.lock().unwrap().push(ObservedQuery {
        name: query.name().to_ascii(),
        record_type: query.query_type(),
    });
}

fn build_response(request: &Message, response: &MockResponse) -> Vec<u8> {
    let query = request.queries().first().unwrap().clone();
    let mut message = Message::new();
    message
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .set_op_code(request.op_code())
        .set_authoritative(true)
        .set_recursion_desired(request.recursion_desired())
        .set_recursion_available(true)
        .add_query(query.clone());

    match response {
        MockResponse::Address(ip) => {
            message.set_response_code(ResponseCode::NoError);
            message.add_answer(Record::from_rdata(
                query.name().clone(),
                60,
                RData::A((*ip).into()),
            ));
        }
        MockResponse::NxDomain => {
            message.set_response_code(ResponseCode::NXDomain);
        }
        MockResponse::Ptr(target) => {
            message.set_response_code(ResponseCode::NoError);
            message.add_answer(Record::from_rdata(
                query.name().clone(),
                60,
                RData::PTR(PTR(Name::from_str(target).unwrap())),
            ));
        }
    }

    message.to_vec().unwrap()
}

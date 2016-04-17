/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>

namespace E
{

struct SocketData
{
	UUID socketUUID;
	int fd;
	int pid;
	uint8_t sa_family;
	uint8_t sin_family;
	uint16_t sin_port;
	struct in_addr sin_addr;
	socklen_t sin_addr_len;
	//uint8_t pin_family;
	//uint16_t pin_port;
	//struct in_addr pin_addr;
};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
	//add------------------------------------------------------------------------------
	virtual void syscall_socket(UUID syscallUUID, int family, int type, int protocol);
	virtual void syscall_close(UUID syscallUUID, int pid, int sockfd);
	virtual void syscall_read(UUID syscallUUID, int pid, int sockfd, void* buffer, size_t len);
	virtual void syscall_write(UUID syscallUUID, int pid, int sockfd, void* buffer, size_t len);
	//read & write - don't have to do now
	virtual void syscall_connect(UUID syscallUUID, int pid, int sockfd, 
		struct sockaddr *serv_addr, socklen_t addrlen);
	virtual void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
	virtual void syscall_accept(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *clientaddr, socklen_t *addrlen);
	virtual void syscall_bind(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *my_addr, socklen_t addrlen);
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *addr, socklen_t *addrlen);
	virtual void syscall_getpeername(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *addr, socklen_t *addrlen);
	std::vector<SocketData*> socketList;
	//----------------------------------------------------------------------------
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
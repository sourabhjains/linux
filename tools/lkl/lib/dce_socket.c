#include <linux/net.h>
#include <linux/errno.h>
#include "dce_init.h"
#include "dce-types.h"
#include "dce_socket.h"
#include "dce_handle_api.h"

#define READ 0
#define WRITE 1

struct DceSocket {};
struct  socket;

static struct iovec *copy_iovec(const struct iovec *input, int len)
{
	int size = sizeof(struct iovec) * len;
	struct iovec *output = lib_malloc(size);

	if (!output)
		return NULL;
	lib_memcpy(output, input, size);
	return output;
}

int dce_sock_socket (int domain, int type, int protocol, struct DceSocket **socket)
{
  struct socket **kernel_socket = (struct socket **)socket;
  int flags;

  /* from net/socket.c */
  flags = type & 0xf;
  if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
    return -EINVAL;
  type &= 0xf;


  int retval = sock_create(domain, type, protocol, kernel_socket);
  struct file *fp = lib_malloc(sizeof(struct file));
  (*kernel_socket)->file = fp;
  fp->f_cred = lib_malloc(sizeof(struct cred));
  return retval;
}

int dce_sock_close (struct DceSocket *socket)
{
  struct socket *kernel_socket = (struct socket *)socket;
  sock_release(kernel_socket);
  return 0;
}

ssize_t dce_sock_recvmsg (struct DceSocket *socket, struct msghdr *msg, int flags)
{
	struct socket *kernel_socket = (struct socket *)socket;
	struct msghdr msg_sys;
	struct cmsghdr *user_cmsgh = msg->msg_control;
	size_t user_cmsghlen = msg->msg_controllen;
	int retval;

	msg_sys.msg_name = msg->msg_name;
	msg_sys.msg_namelen = msg->msg_namelen;
	msg_sys.msg_control = msg->msg_control;
	msg_sys.msg_controllen = msg->msg_controllen;
	msg_sys.msg_flags = flags;

	iov_iter_init(&msg_sys.msg_iter, READ,
		msg->msg_iov, msg->msg_iovlen, iov_size(msg));

	retval = sock_recvmsg(kernel_socket, &msg_sys, iov_size(msg), flags);

	msg->msg_name = msg_sys.msg_name;
	msg->msg_namelen = msg_sys.msg_namelen;
	msg->msg_control = user_cmsgh;
	msg->msg_controllen = user_cmsghlen - msg_sys.msg_controllen;
	return retval;
}

ssize_t dce_sock_sendmsg (struct DceSocket *socket, const struct msghdr *msg, int flags)
{
	struct socket *kernel_socket = (struct socket *)socket;
	struct iovec *kernel_iov = copy_iovec(msg->msg_iov, msg->msg_iovlen);
	struct msghdr msg_sys;
	int retval;

	msg_sys.msg_name = msg->msg_name;
	msg_sys.msg_namelen = msg->msg_namelen;
	msg_sys.msg_control = msg->msg_control;
	msg_sys.msg_controllen = msg->msg_controllen;
	msg_sys.msg_flags = flags;

	iov_iter_init(&msg_sys.msg_iter, WRITE,
		kernel_iov, msg->msg_iovlen, iov_size(msg));

	retval = sock_sendmsg(kernel_socket, &msg_sys);
	lib_free(kernel_iov);
	return retval;
}

int dce_sock_getsockname (struct DceSocket *socket, struct sockaddr *name, int *namelen)
{
  struct socket *kernel_socket = (struct socket *)socket;
  int error = kernel_socket->ops->getname(kernel_socket, name, namelen, 0);
  return error;
}

int dce_sock_getpeername (struct DceSocket *socket, struct sockaddr *name, int *namelen)
{
  struct socket *kernel_socket = (struct socket *)socket;
  int error = kernel_socket->ops->getname(kernel_socket, name, namelen, 1);

  return error;
}

int dce_sock_bind (struct DceSocket *socket, const struct sockaddr *name, int namelen)
{
  struct socket * kernel_socket = (struct socket *)socket;
  struct sockaddr_storage address;

  memcpy(&address, name, namelen);
  int error = kernel_socket->ops->bind(kernel_socket, (struct sockaddr *)&address, namelen);
  return error;
}

int dce_sock_connect (struct DceSocket *socket, const struct sockaddr *name, int namelen, int flags)
{
  struct socket *kernel_socket = (struct socket *)socket;
  struct sockaddr_storage address;

  memcpy(&address, name, namelen);

  kernel_socket->file->f_flags = flags;
  int retval = kernel_socket->ops->connect(kernel_socket, (struct sockaddr *)&address,
          namelen, flags);
  return retval;
}

int dce_sock_listen (struct DceSocket *socket, int backlog)
{
  struct socket * kernel_socket = (struct socket *)socket;
  int error = kernel_socket->ops->listen(kernel_socket, backlog);
  return error;
}

int dce_sock_shutdown (struct DceSocket *socket, int how)
{
  struct socket *kernel_socket = (struct socket *)socket;
  int retval = kernel_socket->ops->shutdown(kernel_socket, how);
  return retval;
}

int dce_sock_accept (struct DceSocket *socket, struct DceSocket **new_socket, int flags)
{
  struct socket *sock, *newsock;
  int err;

  sock = (struct socket *)socket;

  /* the fields do not matter here. If we could, */
  /* we would call sock_alloc but it's not exported. */
  err = sock_create_lite(0, 0, 0, &newsock);
  if (err < 0)
    return err;
  newsock->type = sock->type;
  newsock->ops = sock->ops;

  err = sock->ops->accept(sock, newsock, flags);
  if (err < 0) {
    sock_release(newsock);
    return err;
  }
  *new_socket = (struct SimSocket *)newsock;
  return 0;
}

int dce_sock_ioctl (struct DceSocket *socket, int request, char *argp)
{
  return 0;
  // Need to create lkl_device first
}

int dce_sock_setsockopt (struct DceSocket *socket, int level, int optname, const void *optval, int optlen)
{
  struct socket *kernel_socket = (struct socket *)socket;
  char *coptval = (char *)optval;
  int error;

  if (level == SOL_SOCKET)
    error = sock_setsockopt(socket, level, optname, coptval, optlen);
  return error;
}

int dce_sock_getsockopt (struct DceSocket *socket, int level, int optname, void *optval, int *optlen)
{
  struct socket *kernel_socket = (struct socket *)socket;
  int error;
  error = sock_getsockopt(socket, level, optname, optval, optlen);
  return error;
}

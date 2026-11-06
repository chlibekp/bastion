/* The backend enum alone, so config headers need not pull in the whole loop API. */
#ifndef BST_IO_BACKEND_KIND_H
#define BST_IO_BACKEND_KIND_H

typedef enum { BST_BACKEND_AUTO, BST_BACKEND_URING, BST_BACKEND_EPOLL } bst_backend;

#endif

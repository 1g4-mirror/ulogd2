#ifndef _NAMESPACE_H_
#define _NAMESPACE_H_

int join_netns_fd(const int target_netns_fd, int *const source_netns_fd_ptr);
int join_netns_path(const char *const target_netns_path,
                    int *const source_netns_fd_ptr);

#endif

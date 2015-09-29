/*
 * log.h
 * Copyright (C) 2018 lilin <lilin@lilin-VB>
 *
 * Distributed under terms of the MIT license.
 */

#ifndef LOG_H
#define LOG_H
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define _AUTH "lilin"
#define _GITHUB "https://github.com/lilin5819/log_h"

#ifndef DEBUG
#define DEBUG
#endif

#ifndef DEBUG

#define LOG_DEF(...)
#define log_tag_base(...)
#define log_base(...)
#define logs(...)
#define log_(...)
#define log_err_base(...)
#define log_e(...)
#define log_d(...)
#define log_u(...)
#define log_ld(...)
#define log_lu(...)
#define log_f(...)
#define log_s(...)
#define log_p(...)
#define log_mem(...)

#define set_log_app(...)
#define set_log_file(...)
#define set_log_mode(...)
#define set_log_max_line(...)
#define ok(...) __VA_ARGS__

#else /* DEBUG */

#define _RED_STR "\033[1;31m"
#define _GRE_STR "\033[1;32m"
#define _YEL_STR "\033[1;33m"
#define _FLASH_STR "\033[5m"
#define _COLOR_END "\033[0m"

#define _BLANK_ERR "blank"
#define _NULL_ERR "NULL"
#define _ASSERT_ERR "assert failed !"

#define _COLOR_MASK 0x03
#define _FLASH_MASK 0x04
#define _TRACE_LINE 0x40
#define _NEW_LINE 0x80

#define _MODE_VERBOSE 0x01
#define _MODE_NO_LINE 0x02
typedef enum _COLOR_T { _GRE, _RED, _YEL, _END, _FLASH } COLOR_T;
static char _COLOR[5][16] = {_GRE_STR, _RED_STR, _YEL_STR, _COLOR_END,
                             _FLASH_STR};
extern char *_log_app_name;
extern unsigned char _log_mode;
extern FILE *_log_fp;
extern int _log_fd;
extern size_t _log_line_sum;
extern size_t _log_max_line;
extern void set_log_app(char *appname);
extern void set_log_file(char *file);
extern void set_log_max_line(size_t max_line);
extern void set_log_mode(unsigned char mode);

#define LOG_DEF()                                                       \
  char *_log_app_name = "";                                             \
  unsigned char _log_mode = _MODE_VERBOSE;             \
  FILE *_log_fp = NULL;                                                 \
  int _log_fd = 0;                                                      \
  size_t _log_line_sum = 0;                                             \
  size_t _log_max_line = 1000;                                         \
  void set_log_app(char *appname) {                                    \
    if (!appname) return;                                               \
    _log_app_name = appname;                                            \
    logs(_GITHUB "\n");                                                 \
    logs("start log app <%s>\n", appname);                              \
  }                                                                     \
  void set_log_mode(unsigned char mode) { _log_mode = mode; }           \
  void set_log_max_line(size_t max_line) { _log_max_line = max_line; }  \
  void set_log_file(char *file) {                                       \
    if (_log_fp) {                                                      \
      fclose(_log_fp);                                                  \
      _log_fp = NULL;                                                   \
    }                                                                   \
    _log_fp = fopen(file, "w+");                                        \
    _log_fd = fileno(_log_fp);                                          \
  }

static inline void log_base(const char flag, const char *tag, const char *file,
                            const char *fun, const int line, const char *fmt,
                            ...) {
  static char buf[512];
  if (!(_log_mode &_MODE_VERBOSE) && !_log_fp) return;

  snprintf(buf, 512, "[%s%s%s]", _COLOR[_YEL], _log_app_name, _COLOR[_END]);
  if(!(_log_mode & _MODE_NO_LINE))
    snprintf(buf + strlen(buf), 512 - strlen(buf), "[%-10s > %-15s > %3d]", file,
            fun, line);
  if (tag)
    snprintf(buf + strlen(buf), 512 - strlen(buf), "[%s%s%s%s]",
             _COLOR[flag & _FLASH], _COLOR[flag & _COLOR_MASK], tag,
             _COLOR[_END]);


  if (_log_mode & _MODE_VERBOSE) {
    fputs(buf, stdout);
    fprintf(stdout,"%s%s",_COLOR[flag & _FLASH], _COLOR[flag & _COLOR_MASK]);
    va_list ap;
    va_start(ap, fmt);
      vfprintf(stdout, fmt, ap);
    va_end(ap);
    fprintf(stdout,"%s",_COLOR[_END]);
    if(flag&_NEW_LINE)
      fputs("\n",stdout);

    fflush(stdout);
  }
  if (_log_fp) {
    if(_log_line_sum == _log_max_line){
      _log_line_sum = 0;
      ftruncate(_log_fd,0);
      lseek(_log_fd,0,SEEK_SET);
    } else
      _log_line_sum ++;
      fputs(buf, _log_fp);
      fprintf(_log_fp,"%s%s",_COLOR[flag & _FLASH], _COLOR[flag & _COLOR_MASK]);
      va_list ap;
      va_start(ap, fmt);
        vfprintf(_log_fp, fmt, ap);
      va_end(ap);
      fprintf(_log_fp,"%s",_COLOR[_END]);
      if(flag&_NEW_LINE)
        fputs("\n",_log_fp);
      fflush(_log_fp);
  }
}

#define log_line(flag, tag, ...)                                        \
  do {                                                                  \
    log_base(flag, tag, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__); \
  } while (0)

#define logs(...) log_line(_GRE, NULL, __VA_ARGS__)
#define log_() log_line(_GRE|_NEW_LINE, NULL, "line")
#define log_tag_base(tag, ...) log_line(_GRE|_NEW_LINE, tag, __VA_ARGS__)
#define log_err_base(MSG, ...) log_line(_RED | _FLASH, MSG, __VA_ARGS__)
#define log_e(...) log_err_base("ERROR", __VA_ARGS__)
#define log_d(N) log_tag_base("int","%s=%d", #N, N)
#define log_u(N) log_tag_base("uint","%s=%u", #N, N)
#define log_ld(N) log_tag_base("long","%s=%ld", #N, N)
#define log_lu(N) log_tag_base("ulong","%s=%lu", #N, N)
#define log_f(N) log_tag_base("float","%s=%f", #N, N)

#define log_p(N)                          \
  do {                                    \
    if (!N)                               \
      log_err_base(_NULL_ERR, "%s\n", #N);       \
    else                                  \
      log_tag_base("pointer", "%s=%p", #N, N); \
  } while (0)
//     string
#define log_s(STR)                               \
  do {                                           \
    if (!STR)                                    \
      log_err_base(_NULL_ERR, "%s\n", #STR);            \
    else if (!((char *)(STR))[0])                \
      log_err_base(_BLANK_ERR, "%s=\"\"\n", #STR);      \
    else                                         \
      log_tag_base("string", "%s=\"%s\"", #STR, STR); \
  } while (0)

#define log_mem(P, LEN)                                     \
  do {                                                      \
    int i = 0;                                              \
    char hexbuf[2*(LEN)+1];                                 \
    hexbuf[2*(LEN)] = '\0';                             \
    for (i = 0; i < LEN; i++) {                             \
      sprintf(hexbuf+2*i, "%02X", ((char *)P)[i] & 0xFF);   \
    }                                                       \
    if (!P)                                                 \
      log_err_base(_NULL_ERR, "%s\n", #P);                         \
    else                                                    \
      log_tag_base("MEMORY", "p:%s addr:%p len:%d HEX:%s", #P, P, LEN,hexbuf); \
  } while (0)

//     assert
#define ok(expr)                                    \
  do {                                              \
    if (!(expr)) log_err_base(_ASSERT_ERR,"assert msg: \"" "%s" "\"\n", #expr); \
  } while (0)

#endif /* DEBUG */


#define log_printf logs
#define log_error log_e
#define log_size log_lu
#define log_int log_d
#define log_uint log_u
#define log_long log_ld
#define log_ulong log_lu
#define log_str log_s
#define log_string log_s
#define log_float log_f
#define log_hex log_mem

#endif /* !LOG_H */

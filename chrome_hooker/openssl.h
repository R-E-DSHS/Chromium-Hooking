#pragma once

// 후킹할 SSL_write함수의 형
typedef int (*SSL_write_Def)(void *, void *, int);
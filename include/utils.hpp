#ifndef OWL_UTILS_HPP
#define OWL_UTILS_HPP

#include "master.hpp"

int onlyMe();
void hideWindow();
char *generateUUID();
int runLikeHell(char **argv);
int hash(const char *s, const int n);
int writePlainText(const char *filename, const char *text);

#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
PostMessage (void *hWnd, int msg, unsigned int wParam, unsigned int lParam)
{
  printf ("PostMessage (%p, %d, %d, %d)\n", hWnd, msg, wParam, lParam);
}

int
SendMessage (void *hWnd, int msg, unsigned int wParam, unsigned int lParam)
{
  printf ("SendMessage (%p, %d, %d, %d)\n", hWnd, msg, wParam, lParam);
}


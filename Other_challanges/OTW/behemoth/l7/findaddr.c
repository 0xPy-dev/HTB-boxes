#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
        printf("%p", getenv(argv[1]));
}

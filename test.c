#include <stdio.h>

typedef struct Node {
    char *data;
    struct Node *next;
} Node;

int main(void) {
    Node node1, node2;
    Node *head = &node1;

    node1.data = "asdf\n";
    node1.next = &node2;
    node2.data = "ghjk\n";
    node2.next = NULL;

    while (head != NULL) {
        printf("%s", head->data);
        head = head->next;
    }

    return 0;
}

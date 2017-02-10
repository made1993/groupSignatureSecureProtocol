#include <stdbool.h>

#include "../include/linkedList.h"

LinkedList * create_list(comparator c) {

  if (c == NULL) return NULL;

  LinkedList * l;

  if ((l = malloc(sizeof(l[0]))) == NULL) return NULL;

  l->cmp = c;
  l->first = NULL;
  l->last = NULL;

  return l;

}

void destroy_node(Node * n) {

  n->data = NULL;
  n->next = NULL;
  free(n);
  n = NULL;

}

int delete_elem_list(LinkedList * l, const void * elem){

  Node * node;
  Node * node_prev;

  if (l == NULL || elem == NULL) return ERR;

  if (is_empty_list(l)) return false;

  node = l->first;
  if (!l->cmp(elem, node->data)){
    l->first = node->next;
    destroy_node(node);
    return true;
  }

  node_prev = l->first;
  node = l->first->next;
  while (node != NULL){
    if (!l->cmp(elem, node->data)){
      if (node->next == NULL){
        l->last = node_prev;
      }
      node_prev->next = node->next;
      destroy_node(node);
      return true;
    }
    node_prev = node;
    node = node->next;
  }
  return false;

}

int is_empty_list(const LinkedList * l) {

  if (l == NULL) return ERR;

  return l->first == NULL ? true : false;

}

const void * find(const void * k, const LinkedList * l) {

  if (k == NULL || l == NULL) return NULL;

  for (Node * n = l->first; n != NULL; n = n->next) {
    if (!l->cmp(k, n->data)) return n->data;
  }

  return NULL;

}

int insert_list(LinkedList * l, const void * elem){

  if (l == NULL || elem == NULL) return ERR;

  Node * node;
  if ((node = malloc(sizeof(node[0]))) == NULL) return ERR;

  node->data = elem;
  node->next = NULL;
  if (is_empty_list(l)){
    l->first = node;
    l->last = node;
    return true;
  }
  l->last->next = node;
  l->last = node;
  return true;

}

void destroy_all_nodes (Node * first){

  if (first != NULL){
    destroy_all_nodes(first->next);
    destroy_node(first);
  }

}

void destroy_list (LinkedList * l){

  if (l != NULL){
    if (!is_empty_list(l)) destroy_all_nodes(l->first);
    l->first = NULL;
    l->last = NULL;
    l->cmp = NULL;
    free(l);
  }

}

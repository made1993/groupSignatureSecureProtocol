#ifndef LIST_H

#include <stdlib.h>

#ifndef ERR
#define ERR -1
#endif

/**
 * Comparator follows the strcmp() paradigm:
 *    · Return 0 if equals
 *    · Return n (positive or negative) that represents the
 *      difference otherwise
 * */

typedef int (*comparator)(const void *a, const void *b);

typedef struct Node{
    const void * data;
    struct Node * next;
} Node;

typedef struct {
    comparator cmp;
    Node * first;
    Node * last;
} LinkedList;


/**
 * @page create_list \b create_list
 *
 * @brief Creates a new list.
 *
 * @param comparacion Pointer to function that campares the key of the data.
 * @return The new list if all was OK, NULL otherwise.
 * @section SYNOPSIS
 *  \b #include \b "/includes/lista.h"
 *  \b lib/libLista.a
 *
 * \b LinkedList* \b create_list(\b comparator comparacion \b)
 *
 * @section descripcion DESCRIPCIÓN
 *
 * This funcition creates a linked list and returns it.
 *
 * recives:
 * 	-A pointer type function that compares two argumets.
 * 	the ponter type funcition must be as this:
 * 	int compare(const void *a, const void *b);
 *
 * @section return RETORNO
 *
 * Retrurn an empty linked list.
 *
 * @section seealso VER TAMBIÉN
 * \b destroy_node(3), \b destroy_list(3), \b delete_elem_list(3),
 * \b is_empty_list(3), \b find(3), \b insert_list(3), \b destroy_all_nodes(3)
 */

LinkedList * create_list(comparator c);

/**
 * @page destroy_node \b destroy_node
 *
 * @brief Destroys a node.
 *
 * @param n Node to be destroyed.
 * @return The destroyed node.
 * @section SYNOPSIS
 *  \b #include \b "/includes/lista.h"
 *  \b lib/libLista.a
 *
 * \b void* \b destroy_node(\b Node * n \b)
 *
 * @section descripcion DESCRIPCIÓN
 *
 * This funcition destroys a node.
 *
 * recives:
 * 	-A node.
 *
 * @section return RETORNO
 *
 * A destroyed node.
 *
 *
 * @section seealso VER TAMBIÉN
 * \b create_list(3), \b destroy_list(3), \b delete_elem_list(3),
 * \b is_empty_list(3), \b find(3), \b insert_list(3), \b destroy_all_nodes(3)
 */

void destroy_node(Node * n);

/**
 * @page delete_elem_list \b delete_elem_list
 *
 * @brief Deletes a element of a list
 * @param l A list.
 * @param elem The element to be deleted.
 * @return int.
 *
 * @section SYNOPSIS
 *  \b #include \b "/includes/lista.h"
 *  \b lib/libLista.a
 *
 *  \b int \b delete_elem_list (\b Lista * l \b , \b void * elem \b )
 *
 * @section descripcion DESCRIPCIÓN
 *
 * This function deletes an element elem of the lis l if this element
 * is in the list.
 *
 * Recives:
 *    - l The list.
 *    - elem The element to be deleted.
 *
 * @section retorno RETORNO
 *
 * 1 On succes, 0 on faliure.
 *
 * @section seealso VER TAMBIÉN
 * \b create_list(3), \b destroy_node(3), \b destroy_list(3),
 * \b is_empty_list(3), \b find(3), \b insert_list(3), \b destroy_all_nodes(3)
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
 */

int delete_elem_list(LinkedList * l, const void * elem);

/**
 * @page delete_elem_list \b delete_elem_list
 *
 * @brief Tells if the list is empty or not.
 * @param l List to check
 * @return -1 if an error happened, TRUE if empty or FALSE if not empty.
 *
 * @section SYNOPSIS
 *  \b #include \b "/includes/lista.h"
 *  \b lib/libLista.a
 *
 *  \b int \b is_empty_list(\b LinkedList * l \b)
 *
 * @section descripcion DESCRIPCIÓN
 * This function tells if the list is empty.
 *
 * recives:
 * 	- l A list
 * @section retorno RETORNO
 *
 * 1 When TRUE, 0 When FALSE, -1 On ERROR.
 *
 * @section seealso VER TAMBIÉN
 * \b create_list(3), \b destroy_node(3), \b destroy_list(3),
 * \b delete_elem_list(3), \b find(3), \b insert_list(3), \b destroy_all_nodes(3)
 */

int is_empty_list(const LinkedList * l);

/**
 * @page find \b find
 *
 * @brief This function is used when you want to find something in the list
 * @param clave Key to be find
 * @param l List to check
 * @return NULL if an error happened, the element of the list.
 *
 * @section SYNOPSIS
 *  \b #include \b ""
 *
 *  \b void \b find \b (\b void *\b )
 *
 * @section descripcion DESCRIPCIÓN
 *
 * When you want to find some element than you introduced in the list
 *
 *
 * You have to pass the key of the element that you want to find, and the list
 * where the element is.
 *
 * @section retorno RETORNO
 * Returns the element
 *
 * @section seealso VER TAMBIÉN
 * \b create_list(3), \b destroy_node(3), \b destroy_list(3),
 * \b delete_elem_list(3),\b is_empty_list(3), \b insert_list(3),
 * \b destroy_all_nodes(3)
 * @section authors AUTOR
 * Silvia Anguita (silvia.anguita@estudiante.uam.es)
 * Ángel Fuente (angel.fuente@estudiante.uam.es)
 */

const void * find(const void * k, const LinkedList *l);

/*
 * @page insert_list \b insert_list
 *
 * @brief Insert an element on a list.
 * @param elem Element to be inserted.
 * @param l List to check.
 * @return -1 if an error ocurred, 1 on succes.
 *
 * @section SYNOPSIS
 *  \b #include \b ""
 *
 *  \b int \b insert_list( \b LinkedList * l \b, \b void * elem \b){
 *
 * @section descripcion DESCRIPCIÓN
 *
 * Inserts an elemet at the end of a linked list.
 *
 * recives:
 * 	- l a linked list.
 *	- elem the element to be inserted.
 *
 * @section retorno RETORNO
 * -1 if an error ocurred, 1 on succes.
 *
 * @section seealso VER TAMBIÉN
 * \b create_list(3), \b destroy_node(3), \b destroy_list(3),
 * \b delete_elem_list(3),\b is_empty_list(3), \b find(3),
 * \b destroy_all_nodes(3)
 */

int insert_list(LinkedList * l, const void * elem);

/**
 * @page destroy_all_nodes \b destroy_all_nodes
 *
 * @brief Destroy all nodes of a list.
 *
 * @param first Node to be destroyed.
 * @return 0 always.
 *
 * @section SYNOPSIS
 *  \b #include \b "/includes/lista.h"
 *  \b lib/libLista.a
 *
 *  \b int \b destroy_all_nodes (\b Nodo * first \b)
 *
 * @section descripcion DESCRIPCIÓN
 *
 * Deletes the "first" node of a list an al the "next" nodes of that node.
 * This function shuld be called from destroy_list(3)
 *
 * recives:
 *    - first The first node of the list
 *
 * @section return RETORNO
 * 0 always.
 *
 * @section seealso VER TAMBIÉN
 * \b create_list(3), \b destroy_node(3), \b destroy_list(3),
 * \b delete_elem_list(3),\b is_empty_list(3), \b find(3), \b insert_list(3)
 *
 * @section authors AUTOR
 * Nestor Campillo (nestor.campillo@estudiante.uam.es)
 * Adrian Bueno (adrian.buenoj@estudiante.uam.es)
 */

void destroy_all_nodes (Node * first);

/**
 * @page destroy_list \b destroy_list
 *
 * @brief Destroya a linked list.
 *
 * @param lista List to be destroyed.
 * @return 0 On succes, -1 if an error ocurred..
 *
 * @section SYNOPSIS
 *  \b #include \b "/includes/lista.h"
 *  \b lib/libLista.a
 *
 *  \b int \b destroy_list (\b Lista * lista \b)
 *
 * @section descripcion DESCRIPCIÓN
 *
 * Destroys the whole list.
 *
 * recives:
 *    - lista List to be destroyed
 *
 * @section return RETORNO
 * 0 On succes, -1 if an error ocurred.
 *
 * @section seealso VER TAMBIÉN
 * \b create_list(3), \b destroy_node(3), \b delete_elem_list(3),
 * \b is_empty_list(3), \b find(3), \b insert_list(3), \b destroy_all_nodes(3)
 *
 * @section authors AUTOR
 * Nestor Campillo (nestor.campillo@estudiante.uam.es)
 * Adrian Bueno (adrian.buenoj@estudiante.uam.es)
 */

void destroy_list (LinkedList * l);

#endif

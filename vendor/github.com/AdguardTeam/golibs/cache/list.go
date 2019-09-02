// Double-linked list
// User adds listItem object into his structure
//  and uses structPtr() to get the pointer to his object by the pointer to listItem object.

package cache

import "unsafe"

type listItem struct {
	next *listItem
	prev *listItem
}

// initialize list
func listInit(l *listItem) {
	l.next = l
	l.prev = l
}

// first list item
func listFirst(l *listItem) *listItem {
	return l.next
}

// last list item
func listLast(l *listItem) *listItem {
	return l.prev
}

// link 2 items to each other
func listLink2(l, r *listItem) {
	l.next = r
	r.prev = l
}

// unlink
func listUnlink(item *listItem) {
	listLink2(item.prev, item.next)
}

// append
func listAppend(item, after *listItem) {
	listLink2(item, after.next)
	listLink2(after, item)
}

// Get pointer to structure object by pointer and offset to its field
// e.g.:
// userObject := (*userStruct)(structPtr(unsafe.Pointer(listPtr), unsafe.Offsetof(userStruct{}.listName)))
func structPtr(fieldPtr unsafe.Pointer, fieldOff uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(fieldPtr) - fieldOff)
}

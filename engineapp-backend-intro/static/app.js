function confirmDelete(e) {
	if (confirm("Are you sure you want to delete?") != true) {
		e.preventDefault();
	}
}

var elems = document.getElementsByClassName("confirmDel");
for (i = 0; i < elems.length; i++){
	var elem = elems[i];
	elem.addEventListener("click", confirmDelete, false);
}
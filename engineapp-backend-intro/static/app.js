function confirmDelete(e) {
	if (confirm("Are you sure you want to delete?") != true) {
		e.preventDefault();
	}
}

var elem = document.getElementById("confirmDel");
elem.addEventListener("click", confirmDelete, false);
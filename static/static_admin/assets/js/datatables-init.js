$(document).ready(function() {
    var dataTable = $('#myTable').DataTable({
        responsive: true
    });
    $('#myTable_length select').addClass('form-select form-control');
    $('#myTable_filter input').addClass('form-control').attr("placeholder", "Search Here");
    $('.dataTables_length').prependTo('#tableRowConut')
    $('.dataTables_filter').prependTo('#tableSearch')
    $('.dataTables_info, .paging_simple_numbers').prependTo('.table-bottom-control')
    $('.paging_simple_numbers .btn').addClass('btn-sm')
    $('.status-dropdown').on('change', function(e){
        var status = $(this).val();
        $('.status-dropdown').val(status)
        dataTable.column(2).search(status).draw();
    })
});
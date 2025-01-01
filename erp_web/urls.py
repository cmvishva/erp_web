"""
URL configuration for erp_web project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.contrib import admin
from django.urls import path,include
from django.conf.urls.static import static
from django.conf.urls.i18n import i18n_patterns

from erp_admin.views import *
from erp_user.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    
    path('rosetta/',include('rosetta.urls')),
    
    path('', adminlogin,name=""),
    
    
    
    path('admin_change_password', admin_change_password,name='admin_change_password'),
    path('adminlogin', adminlogin,name="adminlogin"),
    path('adminregister', adminregister,name="adminregister"),
    path('admin_logout', admin_logout,name="admin_logout"),
    
    path('admin_dashboard', admin_dashboard,name='admin_dashboard'),
    # path('add_main_menu', add_mainmenu,name='add_main_menu'),
    # path('view_main_menu', view_mainmenu,name='view_main_menu'),
    # path('delete_main_menu/<int:id>', view_mainmenu,name='delete_main_menu'),
    # path('update_main_menu/<int:id>', update_mainmenu,name='update_main_menu'),
    
    
    #==================================== Branch Page ==============================================
     path('add_branch', add_branch,name='add_branch'),
     path('view_branch',viewbranch,name='view_branch'),
     path('view_branch_fulldetails/<int:branch_id>',viewbranch_fulldetails,name='view_branch_fulldetails'),
     path('delete_branch/<int:branch_id>',deletebranch,name='delete_branch'), 
     path('update_branch/<int:branch_id>',updatebranch,name='update_branch'), 
    
     #==================================== Employee Page ==============================================
     path('register_employee', registeremployee,name='register_employee'),
     path('manage_employee',manageemployee,name='manage_employee'),
     path('view_employee_fulldetails/<int:emp_id>',employee_fulldetails,name='view_employee_fulldetails'),
     path('delete_employee/<int:emp_id>',deleteemployee,name='delete_employee'), 
     path('update_employee/<int:emp_id>',updateemployee,name='update_employee'), 
     
    #==================================== leads entry Page ==============================================
     path('add_leadsentry', add_leadsentry,name='add_leadsentry'),
     path('view_leadsentry',view_leadsentry,name='view_leadsentry'),
    #  path('view_branch_fulldetails/<int:branch_id>',viewbranch_fulldetails,name='view_branch_fulldetails'),
     path('delete_leadsentry/<int:id>',delete_leadsentry,name='delete_leadsentry'), 
     path('update_leadsentry/<int:id>',update_leadsentry,name='update_leadsentry'), 
     
     
      #==================================== Sales Report Page ==============================================
     path('add_salesreport', add_salesreport,name='add_salesreport'),
     path('manage_salesreport',manage_salesreport,name='manage_salesreport'),
    #  path('view_branch_fulldetails/<int:branch_id>',viewbranch_fulldetails,name='view_branch_fulldetails'),
     path('delete_salesreport/<int:id>',delete_salesreport,name='delete_salesreport'), 
     path('update_salesreport/<int:id>',update_salesreport,name='update_salesreport'), 
     
     #==================================== Purchase Report Page ==============================================
     path('add_purchasereport', add_purchasereport,name='add_purchasereport'),
     path('manage_purchasereport',manage_purchasereport,name='manage_purchasereport'),
    #  path('view_branch_fulldetails/<int:branch_id>',viewbranch_fulldetails,name='view_branch_fulldetails'),
     path('delete_purchasereport/<int:id>',delete_purchasereport,name='delete_purchase_report'), 
     path('update_purchasereport/<int:id>',update_purchasereport,name='update_purchasereport'), 
     path('add_vender/', add_vender, name='add_vender'),
    # path('view_venders/', view_venders, name='view_venders'),
     
    #==================================== Quotation Report Page ============================================== 
     path('add_quotation', add_quotation,name='add_quotation'),
     path('manage_quotation', manage_quotation,name='manage_quotation'),
     path('update_quotation/<int:id>', update_quotation,name='update_quotation'),
     path('delete_quotation/<int:id>', delete_quotation,name='delete_quotation'),
     path('quotation_fulldetails/<int:id>', quotation_fulldetails,name='quotation_fulldetails'),
     
     #==================================== To Do Work Page ==============================================
     path('add_todowork', add_todowork,name='add_todowork'),
     path('manage_todowork',manage_todowork,name='manage_todowork'),
    #  path('view_branch_fulldetails/<int:branch_id>',viewbranch_fulldetails,name='view_branch_fulldetails'),
     path('delete_todowork/<int:id>',delete_todowork,name='delete_todowork'), 
     path('update_todowork/<int:id>',update_todowork,name='update_todowork'), 
     
     
     #==================================== Manager Page ==============================================
    #  path('register_manager', registermanager,name='register_manager'),
    #  path('manage_managers',managemanager,name='manage_managers'),
    #  path('delete_manager/<int:manager_id>',deletemanager,name='delete_manager'), 
    #  path('update_manager/<int:manager_id>',updatemanager,name='update_manager'), 
    #  path('view_manager_fulldetails/<int:manager_id>',manager_fulldetails,name='view_manager_fulldetails'),
     
     
     #==================================== Payroll Page ==============================================
     path('add_payroll_details', addpayroll,name='add_payroll_details'),
     path('manage_payroll_details',viewpayroll,name='manage_payroll_details'),
    #  path('view_employee_fulldetails/<int:emp_id>',employee_fulldetails,name='view_employee_fulldetails'),
     path('delete_payroll_details/<int:emp_id>',deletepayroll,name='delete_payroll_details'), 
     path('update_payroll_details/<int:emp_id>',updatepayroll,name='update_payroll_details'), 
     
      
    #==================================== Leave Policy Page ==============================================
    #  path('view_employee_fulldetails/<int:emp_id>',employee_fulldetails,name='view_employee_fulldetails'),
     path('delete_leave/<int:emp_id>',deleteleave,name='delete_leave'),  
     path('manage_leaves',manage_leaves,name='manage_leaves'), 
     path('admin_approve_leave/<int:id>',admin_approve_leave,name='admin_approve_leave'), 
     path('admin_disapprove_leave/<int:id>',admin_disapprove_leave,name='admin_disapprove_leave'), 
     
    #==================================== Report Page ==============================================
     path('add_report_details', addreport,name='add_report_details'),
     path('manage_report_details',viewreport,name='manage_report_details'),
    #  path('view_employee_fulldetails/<int:emp_id>',employee_fulldetails,name='view_employee_fulldetails'),
     path('update_report_details/<int:emp_id>',updatereport,name='update_report_details'), 
     path('delete_report_details/<int:emp_id>',deletereport,name='delete_report_details'), 
     
    #==================================== Rights Roles Page ==============================================
     path('add_rights_roles_details', addrightsroles,name='add_rights_roles_details'),
     path('manage_rights_roles_details',viewrightsroles,name='manage_rights_roles_details'),
    #  path('view_employee_fulldetails/<int:emp_id>',employee_fulldetails,name='view_employee_fulldetails'),
     path('update_rights_roles_details/<int:emp_id>',updaterightsroles,name='update_rights_roles_details'), 
     path('delete_rights_roles_details/<int:emp_id>',deleterightsroles,name='delete_rights_roles_details'), 
     
     #==================================== Employee Work Page ==============================================
     path('add_employee_work_details', addempwork,name='add_employee_work_details'),
     path('manage_employee_work_details',viewempwork,name='manage_employee_work_details'),
    #  path('view_employee_fulldetails/<int:emp_id>',employee_fulldetails,name='view_employee_fulldetails'),
     path('update_employee_work_details/<int:emp_id>',updateempwork,name='update_employee_work_details'), 
     path('delete_employee_work_details/<int:emp_id>',deleteempwork,name='delete_employee_work_details'), 
     
    #==================================== Attendence Page ==============================================
     path('add_attendance_details', addattendance,name='add_attendance_details'),
     path('manage_attendance_details',manageattendance,name='manage_attendance_details'),
    #  path('view_employee_fulldetails/<int:emp_id>',employee_fulldetails,name='view_employee_fulldetails'),
     path('update_attendance_details/<int:id>',updateattendance,name='update_attendance_details'), 
     path('delete_attendance_details/<int:id>',deleteattendance,name='delete_attendance_details'), 
     
     #==================================== Data Entry Page ==============================================
     path('add_data_details', adddata,name='add_data_details'),
     path('manage_data_details',adddata,name='manage_data_details'),
    #  path('view_employee_fulldetails/<int:emp_id>',employee_fulldetails,name='view_employee_fulldetails'),
     path('update_data_details/<int:emp_id>',updatedata,name='update_data_details'), 
     path('delete_data_details/<int:emp_id>',deletedata,name='delete_data_details'), 
     
     
     
     
     
    # +++++++++++++++++++++++++++++++++++++++++++++++++++++ Employee Side ++++++++++++++++++++++++++++++++++++++++++++++++++ 
    
    #==================================== Apply For Leave Page ==============================================
     path('employee_dashboard', employee_dashboard,name='employee_dashboard'),
     
     
     path('employee_add_salesreport', emp_add_salesreport,name='employee_add_salesreport'),
     path('employee_view_salesreport', emp_view_salesreport,name='employee_view_salesreport'),
     
     path('employee_add_salesreport', emp_add_salesreport,name='employee_add_salesreport'),
     path('employee_update_salesreport/<int:id>', emp_update_salesreport,name='employee_add_salesreport'),
     path('employee_delete_salesreport/<int:id>', emp_delete_salesreport,name='employee_add_salesreport'),
     path('employee_view_salesreport', emp_view_salesreport,name='employee_view_salesreport'),
     
     path('employee_add_purchasereport', emp_add_purchasereport,name='employee_add_purchasereport'),
     path('employee_view_purchasereport', emp_view_purchasereport,name='employee_view_purchasereport'),
     path('employee_update_purchasereport/<int:id>', emp_update_purchasereport,name='employee_update_purchasereport'),
     path('employee_delete_purchasereport/<int:id>', emp_delete_purchasereport,name='employee_delete_purchasereport'),
     
     path('employee_add_leadsentry', emp_add_leadsentry,name='employee_add_leadsentry'),
     path('employee_view_leadsentry', emp_view_leadsentry,name='employee_view_leadsentry'),
     path('employee_update_leadsentry/<int:id>', emp_update_leadsentry,name='employee_update_leadsentry'),
     path('employee_delete_leadsentry/<int:id>', emp_delete_leadsentry,name='employee_delete_leadsentry'),
     
     path('employee_add_todowork', emp_add_todowork,name='employee_add_todowork'),
     path('employee_view_todowork', emp_view_todowork,name='employee_view_todowork'),
     path('employee_update_todowork/<int:id>', emp_update_todowork,name='employee_update_todowork'),
     path('employee_delete_todowork/<int:id>', emp_delete_todowork,name='employee_delete_todowork'),
     
     path('employee_applyfor_leave', employee_applyfor_leave,name='employee_applyfor_leave'),
     path('employee_view_leave',employee_viewleave,name='employee_view_leave'),
     path('employee_delete_leave/<int:id>',employee_deleteleave,name='employee_delete_leave'), 
     path('employee_update_leave/<int:id>',employee_updateleave,name='employee_update_leave'),
     
    
     path('employee_add_quotation', emp_addquotation,name='employee_add_quotation'),
     path('employee_view_quotation', emp_viewquotation,name='employee_view_quotation'),
     path('employee_quotation_fulldetails/<int:id>', emp_quotation_fulldetails,name='employee_quotation_fulldetails'),
     path('employee_update_quotation/<int:id>', emp_updatequotation,name='employee_update_quotation'),
     path('employee_delete_quotation/<int:id>', emp_deletequotation,name='employee_delete_quotation'),
     
     
    #  path('download_sales_pdf',download_excel_salesreport,name='download_sales_pdf'),
     path('export_sales_to_excel',export_sales_to_excel,name='export_sales_to_excel'),
     path('download_excel_salesreport',download_excel_salesreport,name='download_excel_salesreport'),
     path('download_quotation_excel',download_excel_data,name='download_quotation_excel'),
     path('download_excel_data',download_excel_data,name='download_excel_data'),
     
     
     path('download_salesreport_pdf/<int:sales_id>/',download_salesreport_pdf,name='download_salesreport_pdf'),
     
     
    # path('mark_attendance', markattendence,name='mark_attendance'),
     
    #  path('employee_addattendance', employee_addattendance,name='employee_addattendance'),
    #  path('employee_view_attendance',employee_viewattendance,name='employee_view_attendance'),
    #  path('employee_delete_attendance/<int:id>',deleteattendance,name='employee_delete_attendance'), 
    #  path('employee_update_attendance/<int:id>',updateattendance,name='employee_update_attendance'),
    
    # path('add_homepage_section1',add_homepage_sec1,name="add_homepage_section1"),
    # path('view_homepage_section1',view_homepage_sec1,name="view_homepage_section1"),
    # path('delete_homepage_section1/<int:id>',delete_homepage_sec1,name="delete_homepage_section1"),
    # path('update_homepage_section1/<int:id>',update_homepage_sec1,name="update_homepage_section1"),
    
    # path('add_homepage_section2',add_homepage_sec2,name="add_homepage_section2"),
    # path('view_homepage_section2',view_homepage_sec2,name="view_homepage_section2"),
    # path('delete_homepage_section2/<int:id>',delete_homepage_sec2,name="delete_homepage_section2"),
    # path('update_homepage_section2/<int:id>',update_homepage_sec2,name="update_homepage_section2"),
    
    # path('add_homepage_section3_maincontent',add_homepage_sec3_maincontent,name="add_homepage_section3_maincontent"),
    # path('view_homepage_section3_maincontent',view_homepage_sec3_maincontent,name="view_homepage_section3_maincontent"),
    # path('delete_homepage_section3_maincontent/<int:id>',delete_homepage_sec3_maincontent,name="delete_homepage_section3_maincontent"),
    # path('update_homepage_section3_maincontent/<int:id>',update_homepage_sec3_maincontent,name="update_homepage_section3_maincontent"),
    
    # path('add_homepage_section3_subcontent',add_homepage_sec3_subcontent,name="add_homepage_section3_subcontent"),
    # path('view_homepage_section3_subcontent',view_homepage_sec3_subcontent,name="view_homepage_section3_subcontent"),
    # path('delete_homepage_section3_subcontent/<int:id>',delete_homepage_sec3_subcontent,name="delete_homepage_section3_subcontent"),
    # path('update_homepage_section3_subcontent/<int:id>',update_homepage_sec3_subcontent,name="update_homepage_section3_subcontent"),
    
    # path('add_homepage_video_section',add_homepage_video_sec,name="add_homepage_video_section"),
    # path('view_homepage_video_section',view_homepage_video_sec,name="view_homepage_video_section"),
    # path('delete_homepage_video_section/<int:id>',delete_homepage_video_sec,name="delete_homepage_video_section"),
    # path('update_homepage_video_section/<int:id>',update_homepage_video_sec,name="update_homepage_video_section"),
    
    # path('',search_image, name='search_image'),
    path('i18n/', include('django.conf.urls.i18n')),
    path(r'set-language/', set_language, name='set_language'),
    
]

urlpatterns += i18n_patterns(
    path('set-language/', include('django.conf.urls.i18n')),
)

handler404 = error_404
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)



from django.db import models

# Create your models here.


from django.utils import timezone
from django.db import models

from django.forms import ModelForm
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin,Group, Permission
from django.contrib.auth.models import AbstractUser
# from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.models import User
from django.utils.translation import gettext_lazy as _


# Create your models here.

class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ('Admin', 'Admin'),
        ('Manager', 'Manager'),
        ('Employee', 'Employee'),
    ]
    
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    
    # Add related_name to avoid conflicts
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='customuser_set',  # Add related_name here
        blank=True,
        help_text=('The groups this user belongs to. A user will get all permissions granted to each of their groups.'),
        verbose_name=('groups'),
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='customuser_permissions',  # Add related_name here
        blank=True,
        help_text=('Specific permissions for this user.'),
        verbose_name=('user permissions'),
    )

class admin_data(models.Model):
    ROLE_CHOICES = [
        ('Admin', 'Admin'),
        ('Manager', 'Manager'),
        ('Employee', 'Employee'),
    ]
    
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=200)

# class ChangePasswordForm(PasswordChangeForm):
#     class Meta:
#         model = admin_data
        
class branches(models.Model):
    name = models.CharField(max_length = 120)
    email = models.EmailField(max_length=120,blank=True)
    code = models.CharField(max_length=120,blank=True)
    address = models.TextField()
    contactno = models.IntegerField(max_length=20)
    manager_name = models.CharField(max_length=120,blank=True)
    manager_email = models.CharField(max_length=120,blank=True)
    oppening_date = models.DateField()
    branch_type = models.CharField(max_length=120,blank=True)

class branch_data(ModelForm):
    class Meta:
        model = branches
        fields = '__all__'
        
class allmanagers(models.Model):
    branch_details = models.ForeignKey(branches,on_delete=models.CASCADE)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    username = models.CharField(max_length=500)
    password = models.CharField(max_length=500)
    joinningdate = models.DateField()
    image = models.FileField(upload_to='media/', blank=True, null=True)
    fname = models.CharField(max_length=120)
    lname = models.CharField(max_length=120)
    surname = models.CharField(max_length=120)
    gender_choices = [
        ('male', ' Male'),
        ('female', 'Female'),
    ]
    gender = models.CharField(max_length=20,choices=gender_choices)
    birthdate = models.DateField()
    email = models.EmailField(max_length=120)
    mobile = models.CharField(max_length=20)
    address = models.TextField()
    
    
class manager_data(ModelForm):
    class Meta:
        model = allmanagers
        fields = ["branch_details","username","password","joinningdate","image","fname","lname","surname","gender","birthdate","email","mobile","address"]
 
        
class jobroles(models.Model):
    jobname = models.CharField(max_length=500)
 
    
class allemployee(models.Model):
    branch_details = models.ForeignKey(branches,on_delete=models.CASCADE)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    # manager_details = models.ForeignKey(allmanagers,on_delete=models.CASCADE)
    username = models.CharField(max_length=500)
    password = models.CharField(max_length=500)
    joinningdate = models.DateField()
    image = models.FileField(upload_to='media/')
    fname = models.CharField(max_length=120)
    lname = models.CharField(max_length=120)
    surname = models.CharField(max_length=120)
    # verificationdoc = models.FileField(upload_to='media/')
    # adharcardno = models.CharField(max_length=1000)
    # jobrole = models.ForeignKey(jobroles, on_delete=models.CASCADE)
    gender_choices = [
        ('male', ' Male'),
        ('female', 'Female'),
    ]
    gender = models.CharField(max_length=20,choices=gender_choices)
    birthdate = models.DateField()
    email = models.EmailField(max_length=120)
    mobile = models.CharField(max_length=20)
    address = models.TextField(default=None)
    # jobrole_agreement = models.FileField(upload_to='media/')
    
    
class employee_data(ModelForm):
    class Meta:
        model = allemployee
        fields = '__all__'    
    
    
       
class salesreport(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    orderid = models.CharField(max_length=100000)
    dateof_sale = models.DateField()
    customer_name = models.CharField(max_length=10000)
    customer_contact = models.CharField(max_length=10000)
    product_name = models.CharField(max_length=10000)
    product_category = models.CharField(max_length=10000,blank=True)
    quantity_sold = models.CharField(max_length=100000)
    payment_methods = [
        ('cash on delivery', 'Cash On Delivery'),
        ('online', 'Online'),
    ]
    payment_method = models.CharField(max_length=500,choices=payment_methods)
    unitprice = models.CharField(max_length=10000)
    total = models.IntegerField()
    status = models.CharField(max_length=10000,blank=True)
    
    
class salesreport_data(ModelForm):
    class Meta:
        model = salesreport
        fields = ["orderid","dateof_sale","customer_name","customer_contact","product_name","product_category","quantity_sold","payment_method","unitprice","total","status"]
        
        
class purchasereport(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    purchaseid = models.CharField(max_length=100000)
    dateof_purchase = models.DateField()
    vendor_name = models.CharField(max_length=10000)
    vendor_contact = models.CharField(max_length=10000)
    product_name = models.CharField(max_length=10000)
    product_category = models.CharField(max_length=10000)
    quantity_purchase = models.CharField(max_length=100000)
    payment_methods = [
        ('cash on delivery', 'Cash On Delivery'),
        ('online', 'Online'),
    ]
    payment_method = models.CharField(max_length=500,choices=payment_methods)
    unitprice = models.CharField(max_length=10000)
    total_purchasecost = models.CharField(max_length=100000)
    status = models.CharField(max_length=10000)
    
    
class purchasereport_data(ModelForm):
    class Meta:
        model = purchasereport
        fields = ["purchaseid","dateof_purchase","vendor_name","vendor_contact","product_name","product_category","quantity_purchase","payment_method","unitprice","total_purchasecost","status"]

class leadsentry(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    fullname = models.TextField(max_length=1000)
    email = models.EmailField(max_length=1000,blank=True)
    phone = models.CharField(max_length=1000,blank=True)
    companyname = models.CharField(max_length=500,blank=True)
    jobtitle = models.CharField(max_length=500,blank=True)
    website = models.TextField(blank=True)
    source = models.TextField(blank=True)
    followup_date = models.DateField(blank=True)
    followup_method = models.CharField(max_length=1200,blank=True)
    budget = models.CharField(max_length=20000,blank=True)
    leadstatus = models.CharField(max_length=1200,blank=True)
    leadowner = models.CharField(max_length=1200,blank=True)
    
class leadsentry_data(ModelForm):
    class Meta:
        model = leadsentry
        fields = ["fullname","email","phone","companyname","jobtitle","website","source","followup_date","followup_method","budget","leadstatus","leadowner"]    
    
        
class leaves(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    branch_details = models.ForeignKey(branches,on_delete=models.CASCADE)
    employee = models.ForeignKey(allemployee, on_delete=models.CASCADE)
    image = models.FileField(upload_to='media/')
    gender_choices = [
        ('male', ' Male'),
        ('female', 'Female'),
    ]
    gender = models.CharField(max_length=20,choices=gender_choices)
    leavesdate = models.DateField()
    leaveedate = models.DateField()
    nofdays = models.TextField()
    reasontype = models.TextField()
    reason = models.TextField()
    document = models.FileField(upload_to='media/')
    STATUS_CHOICES = [
        ('Pending', 'pending'),
        ('Approved', 'approved'),
        ('Disapproved', 'disapproved'),
    ]
    leavestatus = models.CharField(max_length=50, choices=STATUS_CHOICES,default="Pending",blank=True)
    email = models.EmailField(max_length=120)
    mobile = models.CharField(max_length=20)
    
class leavedata(ModelForm):
    class Meta:
        model = leaves
        fields = ["employee","branch_details","image","gender","leavesdate","leaveedate","leavestatus","nofdays","reasontype","reason","document","email","mobile"]    
        
class attendences(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    branch_details = models.ForeignKey(branches,on_delete=models.CASCADE)
    aemp = models.ForeignKey(allemployee, on_delete=models.CASCADE,blank=True,null=True)
    am = models.ForeignKey(allmanagers, on_delete=models.CASCADE,blank=True,null=True)
    date = models.DateField(default=timezone.now)
    # in_time = models.TimeField(null=True, blank=True)
    # out_time = models.TimeField(null=True, blank=True)
    total_hours = models.DurationField(null=True, blank=True)
    STATUS_CHOICES = [
        ('Full Day', 'Full Day'), 
        ('Half Day', 'Half Day'),
        ('Absent', 'Absent'),
    ]
    status = models.CharField(max_length=50, choices=STATUS_CHOICES,default="Absent")
    
class attendence_data(ModelForm):
    class Meta:
        model = attendences
        fields = ["branch_details","aemp","am","date","status","total_hours"]    
     
     
class todowork(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    fullname = models.ForeignKey(allemployee,on_delete=models.CASCADE,blank=True)
    work = models.TextField()
    start_date = models.DateField()
    end_date = models.DateField()
    work_desc = models.TextField()
    status_choices = [
        ('inprocess', 'Inprocess'),
        ('completed','Completed'),
        ('cancel','Cancel')
    ]
    status = models.CharField(max_length=1000)
    delay_reason = models.TextField(blank=True)

class todowork_data(ModelForm): 
    class Meta:
        model = todowork
        fields = ["fullname","work","start_date","end_date","work_desc","status","delay_reason"]
        
        
class quotation_details(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    quotation_header = models.CharField(max_length=10000,blank=True)
    consignee_name = models.CharField(max_length=10000,blank=True)
    consignee_address = models.TextField(blank=True)
    pi_no = models.CharField(max_length=10000,blank=True)
    date = models.DateField(blank=True)
    clearing_port = models.CharField(max_length=10000,blank=True)
    product_name = models.CharField(max_length=10000,blank=True)
    exchange_rate = models.CharField(max_length=10000,blank=True)
    
    fortyfive_container = models.CharField(max_length=10000,blank=True)
    forty_container = models.CharField(max_length=10000,blank=True)
    twenty_container = models.CharField(max_length=10000,blank=True)
    
    sl_qty_cont = models.CharField(max_length=10000,blank=True)
    sl_inr_per_cont = models.CharField(max_length=10000,blank=True)
    sl_gst_18 = models.CharField(max_length=10000,blank=True)
    sl_total_inr = models.CharField(max_length=10000,blank=True)
    
    cfs_qty_cont = models.CharField(max_length=10000)
    cfs_inr_per_cont = models.CharField(max_length=10000,blank=True)
    cfs_gst_18 = models.CharField(max_length=10000,blank=True)
    cfs_total_inr = models.CharField(max_length=10000,blank=True)
    
    transportation_qty_cont = models.CharField(max_length=10000,blank=True)
    transportation_inr_per_cont = models.CharField(max_length=10000,blank=True)
    transportation_gst_18 = models.CharField(max_length=10000,blank=True)
    transportation_total_inr = models.CharField(max_length=10000,blank=True)
    
    stamp_qty_cont = models.CharField(max_length=10000,blank=True)
    stamp_inr_per_cont = models.CharField(max_length=10000,blank=True)
    stamp_gst_18 = models.CharField(max_length=10000)
    stamp_total_inr = models.CharField(max_length=10000)
    
    agency_qty_cont = models.CharField(max_length=10000,blank=True)
    agency_inr_per_cont = models.CharField(max_length=10000,blank=True)
    agency_gst_18 = models.CharField(max_length=10000,blank=True)
    agency_total_inr = models.CharField(max_length=10000,blank=True)
    
    customduty_qty_cont = models.CharField(max_length=10000)
    customduty_inr_per_cont = models.CharField(max_length=10000)
    customduty_gst_18 = models.CharField(max_length=10000)
    customduty_total_inr = models.CharField(max_length=10000)
    
    oceanfreight_qty_cont = models.CharField(max_length=10000,blank=True)
    oceanfreight_inr_per_cont = models.CharField(max_length=10000,blank=True)
    oceanfreight_gst_18 = models.CharField(max_length=10000,blank=True)
    oceanfreight_total_inr = models.CharField(max_length=10000,blank=True)
    
    round_off = models.CharField(max_length=10000,blank=True)
    total = models.CharField(max_length=10000,blank=True)
    ac_name = models.CharField(max_length=10000,blank=True)
    bank_name = models.CharField(max_length=10000,blank=True)
    ac_no = models.CharField(max_length=10000,blank=True)
    ifsc_code = models.CharField(max_length=10000,blank=True)
    pan_no = models.CharField(max_length=10000,blank=True)
    gst_no = models.CharField(max_length=10000,blank=True)
    
class quotation_data(ModelForm):
    class Meta:
        model = quotation_details
        fields = ["quotation_header","consignee_name","consignee_address","pi_no","date","clearing_port","product_name","exchange_rate","fortyfive_container","forty_container","twenty_container",
                  "sl_qty_cont","sl_inr_per_cont","sl_gst_18","sl_total_inr",
                  "cfs_qty_cont","cfs_inr_per_cont","cfs_gst_18","cfs_total_inr",
                  "transportation_qty_cont","transportation_inr_per_cont","transportation_gst_18","transportation_total_inr",
                  "stamp_qty_cont","stamp_inr_per_cont","stamp_gst_18","stamp_total_inr",
                  "agency_qty_cont","agency_inr_per_cont","agency_gst_18","agency_total_inr",
                  "customduty_qty_cont","customduty_inr_per_cont","customduty_gst_18","customduty_total_inr",
                  "oceanfreight_qty_cont","oceanfreight_inr_per_cont","oceanfreight_gst_18","oceanfreight_total_inr",
                  "round_off","total","ac_name","bank_name","ac_name","bank_name","ac_no","ifsc_code","pan_no","gst_no"]
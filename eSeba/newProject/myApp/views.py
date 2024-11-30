from django.conf import settings
from django.contrib import messages
from django.contrib.auth import (
    authenticate,
    login as auth_login,
    logout as auth_logout
)
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.db.models import Prefetch, Q, Sum
from django.shortcuts import (
    get_object_or_404,
    redirect,
    render
)
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string

from .forms import Captcha, UserForm, UserProfileForm
from .models import *

import logging


def home(request):
    return render(request, "home.html")

# Login View
def login(request):
    if request.method == "POST":
        form = Captcha(request.POST)

        if form.is_valid():
            username = request.POST.get("u_name")
            password = request.POST.get("u_password")

            # Check if username and password are provided
            if not username or not password:
                messages.error(request, "Username and password are required.")
                return redirect("login")

            # Authenticate the user
            authenticated_user = authenticate(request, username=username, password=password)

            if authenticated_user is not None:
                auth_login(request, authenticated_user)
                messages.success(request, f"Welcome, {username}!")
                return redirect("home")
            else:
                messages.error(request, "Invalid username or password.")
        else:
            messages.error(request, "reCAPTCHA verification failed. Please try again.")

    else:
        form = Captcha()

    return render(request, "login.html", {"form": form})

# Send OTP Email
logger = logging.getLogger(__name__)
def send_otp_email(email, otp):
    try:
        subject = 'OTP Verification'
        message = f'Your OTP is: {otp}. It is valid for 10 minutes.'
        sender_email = settings.EMAIL_FROM
        recipient_list = [email]

        send_mail(subject, message, sender_email, recipient_list, fail_silently=False)
        logger.info(f"OTP sent to {email}")
        
    except Exception as e:
        logger.error(f"Error sending OTP to {email}: {e}")

def register(request):
    if request.method == "POST":
        form = Captcha(request.POST)

        if form.is_valid():
            # Get cleaned data from the form
            u_name = request.POST.get("u_name")
            u_fname = request.POST.get("u_fname")
            u_lname = request.POST.get("u_lname")
            u_email = request.POST.get("u_email")
            u_password = request.POST.get("u_password")
            u_age = request.POST.get("u_age")
            u_address = request.POST.get("u_address")
            u_mobile = request.POST.get("u_mobile")
            u_gender = request.POST.get("u_gender")

            # Email uniqueness check
            if User.objects.filter(email=u_email).exists():
                messages.error(request, "Email already in use. Please try another one.")
                return redirect('register')
            
            # Generate OTP and send it to the user via email
            otp_generated = get_random_string(length=6, allowed_chars='1234567890')
            send_otp_email(u_email, otp_generated)  # Ensure this function is defined
            print(f"Generated OTP for {u_email}: {otp_generated}")  # For debugging purposes

            # Store form data and OTP in session for verification in the next step
            request.session['u_name'] = u_name
            request.session['u_fname'] = u_fname
            request.session['u_lname'] = u_lname
            request.session['u_email'] = u_email
            request.session['u_password'] = u_password
            request.session['u_age'] = u_age
            request.session['u_address'] = u_address
            request.session['u_mobile'] = u_mobile
            request.session['u_gender'] = u_gender
            request.session['otp_generated'] = otp_generated  

            return redirect('verify_otp')
        else:
            messages.error(request, "CAPTCHA verification failed. Please try again.")
        
    else:
        form = Captcha()

    return render(request, "register.html", {"form": form})

def verify_otp(request):
    # Retrieve email from session
    u_email = request.session.get('u_email')

    if request.method == 'POST':
        otp_entered = request.POST.get('otp')
        otp_generated = request.session.get('otp_generated')  

        # Get user details from session
        u_name = request.session.get('u_name')
        u_fname = request.session.get('u_fname')
        u_lname = request.session.get('u_lname')
        u_password = request.session.get('u_password')
        u_age = request.session.get('u_age')
        u_address = request.session.get('u_address')
        u_mobile = request.session.get('u_mobile')
        u_gender = request.session.get('u_gender')

        # Check if the entered OTP matches the generated OTP
        if otp_entered == otp_generated:
            # Create the user
            user = User.objects.create_user(
                username=u_name,
                first_name=u_fname,
                last_name=u_lname,
                email=u_email,
                password=u_password
            )

            # Create the user profile
            user_profile = UserProfile(
                user=user,
                age=u_age,
                address=u_address,
                mobile=u_mobile,
                gender=u_gender
            )
            user_profile.save()
            
            # Authenticate and log in the user
            authenticated_user = authenticate(request, username=u_name, password=u_password)
            if authenticated_user:
                auth_login(request, authenticated_user) 
                messages.success(request, "Your account has been successfully created.")
                # Clear sensitive session data after success
                for key in ['u_name', 'u_fname', 'u_lname', 'u_email', 'u_password', 
                            'u_age', 'u_address', 'u_mobile', 'u_gender', 'otp_generated']:
                    request.session.pop(key, None)  # Safely remove keys from session

                return redirect("home")
            else:
                messages.error(request, "Authentication failed. Please try again.")
        else:
            messages.error(request, "Invalid OTP. Please try again.")

    # Render the OTP verification template with the email
    return render(request, 'verify_otp.html', {'email': u_email})

def user_profile(request):
    user_profile = UserProfile.objects.get(user=request.user)
    profile_form = UserProfileForm(instance=user_profile)
    user_form = UserForm(instance=request.user)
    appointments = Appointment.objects.filter(user=request.user)
    
    bills = Bill.objects.filter(customer=request.user).prefetch_related(
        Prefetch('billitem_set', queryset=BillItem.objects.select_related('accessory'))
    ).annotate(total_item_cost=Sum('billitem__total_cost'))

    if request.method == "POST":
        if "delete_account" in request.POST:
            request.user.delete()
            auth_logout(request)
            messages.success(request, "Your account has been deleted.")
            return redirect('login')

        profile_form = UserProfileForm(request.POST, instance=user_profile)
        user_form = UserForm(request.POST, instance=request.user)

        if profile_form.is_valid() and user_form.is_valid():
            profile_form.save()
            user_form.save()
            messages.success(request, "Profile updated successfully.")
            return redirect('user_profile')
        else:
            messages.error(request, "Error updating profile. Please check the form.")

    context = {
        'user_profile': user_profile,
        'profile_form': profile_form,
        'user_form': user_form,
        'appointments': appointments,
        'bills': bills
    }
    return render(request, 'user_profile.html', context)

@login_required
def logout(request): 
    user = request.user
    CartItem.objects.filter(user=user).delete()
    
    auth_logout(request)
    messages.success(request, "Logged out Successfully!")
    return redirect('home')

def products(request):
    products = MedicalAccessories.objects.all()

    context = {
        'products': products,
        }

    return render(request, 'products.html', context)

def product_search(request):
    query = request.GET.get('q')
    
    if query:
        # Check if the query matches a category
        category_match = dict(MedicalAccessories.CATEGORY).get(query.capitalize())
        
        if category_match:
            # If it matches a category, filter by category
            products = MedicalAccessories.objects.filter(p_category=category_match)
        else:
            # Otherwise, search by product name or description
            products = MedicalAccessories.objects.filter(
                Q(p_name__icontains=query) | Q(p_description__icontains=query)
            )
    else:
        messages.error(request, "Search bar was empty")
        return redirect('products')
    
    if not products.exists():
        messages.error(request, "No product found")
        return redirect('products')

    context = {
        'products': products,
    }
    return render(request, 'products.html', context)


@login_required
def cart(request):
    
    user = request.user
    cart_items = CartItem.objects.filter(user=user)

    for item in cart_items:
        item.total_cost = item.accessory.p_cost * item.quantity
        
        
    total_cost = sum(item.total_cost for item in cart_items)
    
    context = {
        'cart_items': cart_items,
        'total_cost': total_cost
        }
    return render(request, 'cart.html', context)

@login_required
def add_to_cart(request, product_id):

    if request.method == 'POST':
        user = request.user
        product = get_object_or_404(MedicalAccessories, pk=product_id)
        quantity = int(request.POST.get('quantity', 0))

        if quantity <= 0:
            messages.error(request, "Add at least 1 item!")
            return redirect(reverse('products'))
        
        if quantity > product.p_count:
            messages.error(request, "Out of stock!")
            return redirect(reverse('products'))

        cart_item, created = CartItem.objects.get_or_create(user=user, accessory=product)

        if created:
            cart_item.quantity = quantity
        else:
            cart_item.quantity += quantity
            
        cart_item.total_cost = cart_item.quantity * cart_item.accessory.p_cost
        cart_item.save()
        messages.success(request, "Successfully added")
        return redirect(reverse('products'))
    else:
        return redirect('products') 

@login_required
def remove_from_cart(request, product_id):
    
    if request.method == 'POST':
        user = request.user
        product = get_object_or_404(MedicalAccessories, pk=product_id)
        cart_item = CartItem.objects.get(user=user, accessory=product)
        cart_item.delete()
        messages.success(request, "Item removed from your cart.")
    return redirect('cart')

@login_required
def update_cart(request, product_id):
    
    if request.method == 'POST':
        user = request.user
        product = get_object_or_404(MedicalAccessories, pk=product_id)
        quantity = int(request.POST.get('quantity', 1))
        cart_item = CartItem.objects.get(user=user, accessory=product)
        
        if quantity > 0:
            cart_item.quantity = quantity
            cart_item.total_cost = cart_item.quantity * cart_item.accessory.p_cost
            cart_item.save()
            messages.success(request, "Cart item updated.")
        else:
            cart_item.delete()
            messages.success(request, "Item removed from your cart.")
        cart_item = CartItem.objects.get(user=user, accessory=product)
        
    return redirect('cart')

@login_required
def checkout(request):
    user = request.user
    cart_items = CartItem.objects.filter(user=user)

    new_bill = Bill.objects.create(customer=user, total_cost=0, created_at=timezone.now())

    for item in cart_items:
        if item.accessory.p_count >= item.quantity:
            item.accessory.p_count -= item.quantity
            item.accessory.save()
            BillItem.objects.create(
                bill=new_bill,
                accessory=item.accessory,
                quantity=item.quantity,               
                total_cost = item.total_cost
            )

    new_bill.save()
    cart_items.delete()
    messages.success(request, "Checkout successful.")   
    context = {
        'new_bill': new_bill,
    }
    return render(request, 'checkout.html', context)


def appointment(request):
    doctors = Doctor.objects.all()
    context = {
        'doctors': doctors
    }
    return render(request, "appointment.html", context)

def doctor_search(request):
    query_d = request.GET.get('q')
    
    if query_d:
        words = query_d.split()
        name_query = Q()
        specialty_query = Q()
        status_query = Q()

        for word in words:
            if word.lower() == "available":
                status_query = Q(status=True)
                
            elif word.lower() == "unavailable":
                status_query = Q(status=False)
                
            else:
                name_query |= Q(name__icontains=word)
                specialty_query |= Q(specialty__icontains=word)

        doctors = Doctor.objects.filter(name_query | specialty_query, status_query)
    else:
        messages.error(request, "Search bar was empty")
        return redirect('appointment')
        
    if not doctors:
        messages.error(request, "No doctors found.")
        return redirect('appointment')

    context = {
        'doctors': doctors,
        }

    return render(request, 'appointment.html', context)

@login_required
def create_appointment(request, doctor_id):
    doctor = Doctor.objects.get(id=doctor_id)
    
    if request.method == 'POST':
        appointment_date = request.POST['appointment_date']
        description = request.POST['description']
        appointment_time_id = request.POST['appointment_time']
        time_slot = DoctorTimeSlot.objects.get(id=appointment_time_id, doctor=doctor)
        selected_date = timezone.datetime.strptime(appointment_date, '%Y-%m-%d').date()
        today = timezone.now().date()

        if not doctor.status:
            doctor.available_spots = doctor.available_spots + 1
            doctor.status = True
            doctor.save()
            # Doctor is unavailable
            if selected_date < doctor.next_available_appointment_date:
                messages.error(request, f"Choose a date after: {doctor.next_available_appointment_date.strftime('%d/%B/%Y')}")
                return redirect(reverse('create_appointment', args=[doctor_id]))
        else:
            if selected_date < today:
                messages.error(request, "Please select an upcoming date.")
                return redirect(reverse('create_appointment', args=[doctor_id]))

        if doctor.available_spots == 0:
            doctor.status = False
        else:
            doctor.status = True
        doctor.save()

        serial_number = Appointment.objects.filter(doctor=doctor).count() + 1

        appointment = Appointment(
            user=request.user,
            doctor=doctor,
            appointment_date=appointment_date,
            description=description,
            doctor_time_slot=time_slot,
            serial_number=serial_number
        )
        appointment.save()

        doctor.available_spots -= 1
        if doctor.available_spots == 0:
            doctor.status = False
        else:
            doctor.status = True
        doctor.save()

        messages.success(request, "Successful appointment made")
        return redirect(reverse('appointment'))

    context ={
        'doctor': doctor
    }
    return render(request, 'create_appointment.html', context)



def cancel_appointment(request, appointment_id, doctor_id):
    appointment = get_object_or_404(Appointment, id=appointment_id)
    doctor = get_object_or_404(Doctor, id=doctor_id)

    if appointment.user == request.user:
        doctor.available_spots += 1
        doctor.save()
        appointment.serial_number -= 1
        appointment.delete()
        messages.success(request, "Appointment canceled successfully.")
    else:
        messages.error(request, "You are not authorized to cancel this appointment.")

    return redirect('user_profile')

def emergency(request):
    hospitals = Hospital.objects.all()
    context = {
        'hospitals': hospitals
    }
    return render(request, "emergency.html", context)

def blood_search(request):
    query = request.GET.get('q')
    hospitals = Hospital.objects.all()

    if query:
        hospitals = hospitals.filter(
            Q(hospital_name__icontains=query) | Q(location__icontains=query) 
            | Q(blood_samples__blood_group__iexact=query)
        ).distinct() 
    else:
        messages.error(request, "Search bar was empty")
        return redirect('emergency')
        
    if not hospitals:
        messages.error(request, "No hospitals found.")
        return redirect('emergency')

    context = {
        'hospitals': hospitals,
    }
    return render(request, 'emergency.html', context)

def about(request):
    return render(request, "about.html")

def custom_error(request,):
    return render(request, 'error.html')

def userManual(request,):
    return render(request, 'userManual.html')
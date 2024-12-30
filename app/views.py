from django.shortcuts import render, redirect
import datetime
from .models import *
from django.http import JsonResponse
import json
from . utils import cookieCart,cartData, guessOrder
from .models import Product
from .utils import cartData  # Asegúrate de tener esta función definida
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.utils.dateparse import parse_date
from django.http import HttpResponse
import re
from django.shortcuts import render, redirect, get_object_or_404
from django.core.exceptions import PermissionDenied
from django.utils.http import urlsafe_base64_decode

from datetime import timedelta
from django import forms
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import PermissionDenied
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.mail import send_mail
from django.http import JsonResponse, HttpResponse,Http404
from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.http import urlsafe_base64_decode
from .models import *

from django.urls import reverse

from django.utils.html import strip_tags
from django.core.mail import send_mail
from django.utils.html import format_html
from django.http import HttpRequest

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.models import User



def store(request, category=None):
    if category:
        # Filtrar productos por la categoría si se pasa como parámetro
        products = Product.objects.filter(category=category)
    else:
        # Si no se pasa categoría, mostrar todos los productos
        products = Product.objects.all()

    # Obtener el número de artículos en el carrito desde la sesión
    cart_items = request.session.get('cart', {}).values()
    cart_items_count = sum(item['quantity'] for item in cart_items)

    context = {
        'products': products,
        'cartItems': cart_items_count,
    }

    return render(request, 'generales/store.html', context)

def audio(request):
    data = cartData(request)
    cartItems = data['cartItems']
    products = Product.objects.filter(category='Audio')
    context = {'products': products, 'cartItems': cartItems}
    return render(request, 'generales/category.html', context)

def cable(request):
    data = cartData(request)
    cartItems = data['cartItems']
    products = Product.objects.filter(category='Cable')
    context = {'products': products, 'cartItems': cartItems}
    return render(request, 'generales/category.html', context)

def seguridad(request):
    data = cartData(request)
    cartItems = data['cartItems']
    products = Product.objects.filter(category='Seguridad')
    context = {'products': products, 'cartItems': cartItems}
    return render(request, 'generales/category.html', context)

def lo_nuevo(request):
    data = cartData(request)
    cartItems = data['cartItems']
    products = Product.objects.filter(category='Lo nuevo')
    context = {'products': products, 'cartItems': cartItems}
    return render(request, 'generales/category.html', context)

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)

            if not hasattr(user, 'customer'):
                Customer.objects.create(user=user)

            messages.success(request, f"¡Bienvenido {username}!")
            return redirect('Tienda')
        else:
            messages.error(request, "Usuario o contraseña incorrectos")
            return redirect('login')
    return render(request, 'generales/login.html')


def register_view(request):
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        dpi = request.POST.get('dpi')
        birth_date = request.POST.get('birth_date')
        phone = request.POST.get('phone')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password_confirmation = request.POST.get('password_confirmation')

        if password != password_confirmation:
            messages.error(request, "Las contraseñas no coinciden")
            return render(request, 'generales/register.html')

        try:
            user = User.objects.create_user(username=username, password=password, email=email)
            user.first_name = first_name
            user.last_name = last_name
            user.save()

            Customer.objects.create(user=user)

            login(request, user)
            messages.success(request, f'¡Bienvenido, {user.username}! Te has registrado correctamente.')

            return redirect('Tienda')  
        except IntegrityError:
            messages.error(request, "El nombre de usuario o el correo electrónico ya está registrado.")
            return render(request, 'generales/register.html')

    return render(request, 'generales/register.html')


def logout_view(request):
    logout(request)
    messages.info(request, 'Has cerrado sesión exitosamente.')
    return redirect('Tienda')

def cart(request):
    
    data = cartData(request)
    cartItems = data['cartItems']
    items = data['items']
    order = data['order']

    context = {'items':items, 'order':order,'cartItems':cartItems, }
    return render(request,'generales/cart.html',context)

def checkout(request):
    
    data = cartData(request)
    cartItems = data['cartItems']
    items = data['items']
    order = data['order']

    context = {'items':items, 'order':order,'cartItems':cartItems}

    return render(request,'generales/checkout.html',context)

def updateItem(request):
    try:
        data = json.loads(request.body)
        productId = data['productId']
        action = data['action']

        if not hasattr(request.user, 'customer'):
            customer = Customer.objects.create(user=request.user)
        else:
            customer = request.user.customer

        product = Product.objects.get(id=productId)
        order, created = Order.objects.get_or_create(customer=customer, complete=False)
        orderItem, created = OrderItem.objects.get_or_create(order=order, product=product)

        if action == 'add':
            orderItem.quantity += 1
        elif action == 'remove':
            orderItem.quantity -= 1

        if orderItem.quantity <= 0:
            orderItem.delete()
        else:
            orderItem.save()

        return JsonResponse('Producto actualizado correctamente', safe=False)
    except Exception as e:
        print(f"Error en updateItem: {e}")
        return JsonResponse('Error al actualizar el producto', safe=False)

def processOrder(request):
    transacion_id = datetime.datetime.now().timestamp()
    data = json.loads(request.body)
    if request.user.is_authenticated:
        customer = request.user.customer
        order, created = Order.objects.get_or_create(customer=customer, complete=False)

    else:
        customer, order = guessOrder(request,data)

    total = float(data['form']['total'])
    order.transaction_id = transacion_id

    if total == order.get_cart_total:
        order.complete = True
    order.save()

    if order.shipping == True:
        ShippingAddress.objects.create(
            customer=customer,
            order=order,
            address=data['shipping']['address'],
            city=data['shipping']['city'],
            state=data['shipping']['state'],
            zipcode=data['shipping']['zipcode'],
        )
    return JsonResponse('Pago completo', safe=False)


def password_reset(request):
    context = {}
    return render(request,'generales/password_reset.html',context)



def set_username_password(request, uidb64, token):
    try:
        # Decodificar el uid
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    # Verifica si el token es válido
    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            username = request.POST.get('username')
            password = request.POST.get('password')

            if username and password:
                # Verifica si el nombre de usuario ya existe
                if User.objects.filter(username=username).exists():
                    messages.error(request, 'El nombre de usuario ya existe. Por favor, elige otro.')
                else:
                    # Asigna el nuevo username y la contraseña
                    user.username = username
                    user.set_password(password)
                    user.save()

                    messages.success(request, 'Nombre de usuario y contraseña actualizados exitosamente.')
                    return redirect('login')  # Redirige al login

        return render(request, 'generales/set_username_password.html', {'validlink': True, 'user': user})
    else:
        messages.error(request, 'El enlace es inválido o ha caducado.')
        return redirect('password_reset')
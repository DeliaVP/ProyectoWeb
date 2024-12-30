from django.contrib import admin
from django.urls import path
from . import views
from django.urls import path
from . import views
from django.contrib.auth import views as auth_views


urlpatterns = [
    path('logout/', views.logout_view, name='logout'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('categoria/<str:category>/', views.store, name='productos_categoria'),  # Aquí pasamos 'category' como parámetro
    path('', views.store, name='Tienda'),  # Vista de tienda general
    path('cart/', views.cart, name='Carrito'),
    path('checkout/', views.checkout, name='Pago'),
    path('audio/', views.audio, name='audio'),
    path('cable/', views.cable, name='cable'),
    path('seguridad/', views.seguridad, name='seguridad'),
    path('lo-nuevo/', views.lo_nuevo, name='lo_nuevo'),
    path('update_item/', views.updateItem, name='update_item'),
    path('process_order/', views.processOrder, name='process_order'),
    path('password_reset/', auth_views.PasswordResetView.as_view(
        template_name='generales/password_reset.html', 
        email_template_name='generales/password_reset_email.html'
    ), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(
        template_name='generales/password_reset_done.html'
    ), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
        template_name='generales/password_reset_confirm.html'
    ), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(
        template_name='generales/password_reset_complete.html'
    ), name='password_reset_complete'),
    path('set_username_password/<uidb64>/<token>/', views.set_username_password, name='set_username_password'),
]

# Usa una imagen base de Python
FROM python:3.10-slim

# Establece una variable de entorno para evitar buffers en logs
ENV PYTHONUNBUFFERED 1

# Instala dependencias del sistema
RUN apt-get update && apt-get install -y \
    libpq-dev gcc

# Define el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia el archivo de requerimientos
COPY requirements.txt .

# Instala las dependencias de Python
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Copia todo el proyecto al contenedor
COPY . .

# Expone el puerto 8000
EXPOSE 8080

# Comando predeterminado para ejecutar el servidor
CMD ["python", "manage.py", "runserver", "0.0.0.0:8080"]
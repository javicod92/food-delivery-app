# Usamos Node.js en una imagen ligera
FROM node:latest

# Directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiamos archivos de configuración
COPY package*.json ./

# Instalamos dependencias
RUN npm install

# Copiamos el resto del código fuente
COPY . .

# Generamos Prisma Client e inicializamos la base de datos
RUN npx prisma generate

# Exponemos el puerto
EXPOSE 5000

# Comando para iniciar el servicio
CMD ["node", "server.js"]

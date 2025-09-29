-- C
CREATE SCHEMA IF NOT EXISTS calc;

SET search_path TO calc;
-- Tabla Empleador
CREATE TABLE Empleador (
	idEmpleador INT NOT NULL,
	codEmpleador VARCHAR(20) NOT NULL,
	nombre VARCHAR(100) NOT NULL,
	telefono VARCHAR(20),
    email VARCHAR(100),
	direccion VARCHAR(300),
	descripcion TEXT,
	contacto VARCHAR(100),
	telefono_contacto VARCHAR(20),
	email_contacto VARCHAR(100),
	fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	usuario_creacion VARCHAR(50),
	fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	usuario_actualizacion VARCHAR(50),
	PRIMARY KEY (idEmpleador, codEmpleador)
);

-- Tabla Empleado
CREATE TABLE Empleado (
	idEmpleado INT NOT NULL,
	identificacion VARCHAR(30) NOT NULL,
	idEmpleador INT NOT NULL,
	codEmpleador VARCHAR(20) NOT NULL,
	nombre VARCHAR(100) NOT NULL,
	correo VARCHAR(100),
	usuario VARCHAR(50),
	telefono VARCHAR(20),
	direccion VARCHAR(200),
	fecha_nacimiento DATE,
	fecha_ingreso DATE,
	estado VARCHAR(20),
	fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	usuario_creacion VARCHAR(50),
	fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	usuario_actualizacion VARCHAR(50),
	PRIMARY KEY (idEmpleado, identificacion),
	FOREIGN KEY (idEmpleador, codEmpleador) REFERENCES Empleador(idEmpleador, codEmpleador)
);


-- Creación del esquema de nómina
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
	idEmpleado BIGINT NOT NULL ,
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

-- Tabla Contrato
CREATE TABLE Contrato (
	idContrato BIGINT NOT NULL ,
	idEmpleado BIGINT NOT NULL,
	identificacion VARCHAR(30) NOT NULL,
	idEmpleador INT NOT NULL,
	codEmpleador VARCHAR(20) NOT NULL,
	tipo_contrato VARCHAR(50) NOT NULL,
	detalle TEXT,
	descripcion VARCHAR(300),
	fecha_inicio DATE NOT NULL,
	fecha_fin DATE,
	estado VARCHAR(20) NOT NULL,
	fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	usuario_creacion VARCHAR(50),
	fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	usuario_actualizacion VARCHAR(50),
	PRIMARY KEY (idContrato),
	FOREIGN KEY (idEmpleado, identificacion) REFERENCES Empleado(idEmpleado, identificacion),
	FOREIGN KEY (idEmpleador, codEmpleador) REFERENCES Empleador(idEmpleador, codEmpleador)
)

-- Tabla Ademdum
CREATE TABLE Ademdum (
	idContrato BIGINT NOT NULL,
	fecha_ademdum DATE NOT NULL,
	tipo_ademdum VARCHAR(100) NOT NULL,
	detalle TEXT,
	descripcion VARCHAR(300),
	fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	usuario_creacion VARCHAR(50),
	fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	usuario_actualizacion VARCHAR(50),
	FOREIGN KEY (idContrato) REFERENCES Contrato(idContrato)
);

-- Tabla Nomina
CREATE TABLE Nomina (
	idNomina BIGINT NOT NULL ,
	idContrato INT NOT NULL,
	periodo_inicio DATE NOT NULL,
	periodo_fin DATE NOT NULL,
	salario_base DECIMAL(10,2) NOT NULL,
	bonificaciones DECIMAL(10,2) DEFAULT 0,
	deducciones DECIMAL(10,2) DEFAULT 0,
	total_pagado DECIMAL(10,2) NOT NULL,
	fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	usuario_creacion VARCHAR(50),
	fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	usuario_actualizacion VARCHAR(50),
	PRIMARY KEY (idNomina),
	FOREIGN KEY (idContrato) REFERENCES Contrato(idContrato)
);

-- Tabla Descuentos
CREATE TABLE Descuentos (
	idNomina BIGINT NOT NULL ,
	tipo_descuento VARCHAR(100) NOT NULL,
	monto DECIMAL(10,2) NOT NULL,
	descripcion TEXT,
	fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	usuario_creacion VARCHAR(50),
	fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	usuario_actualizacion VARCHAR(50),
	FOREIGN KEY (idNomina) REFERENCES Nomina(idNomina)
);

-- Tabla Ingresos
CREATE TABLE Ingresos (
	idNomina BIGINT NOT NULL ,
	tipo_bonificacion VARCHAR(100) NOT NULL,
	monto DECIMAL(10,2) NOT NULL,
	descripcion TEXT,
	fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	usuario_creacion VARCHAR(50),
	fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	usuario_actualizacion VARCHAR(50),
	FOREIGN KEY (idNomina) REFERENCES Nomina(idNomina)
);



	
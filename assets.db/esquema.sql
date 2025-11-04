SET search_path TO sncyt;

-- Table: sncyt.letrado
DROP TABLE IF EXISTS sncyt.letrado;



CREATE TABLE IF NOT EXISTS sncyt.letrado
(
    identificacion character varying(20) COLLATE pg_catalog."default" NOT NULL,
    nombre text COLLATE pg_catalog."default" NOT NULL,
    genero character varying(20) COLLATE pg_catalog."default",
    nacionalidad character varying(50) COLLATE pg_catalog."default",
    update_time date,
    CONSTRAINT letrado_pkey PRIMARY KEY (identificacion)
)



-- Table: sncyt.titulo

DROP TABLE IF EXISTS sncyt.titulo;
CREATE TABLE IF NOT EXISTS sncyt.titulo
(
    letrado_id character varying(20) COLLATE pg_catalog."default",
    titulo text COLLATE pg_catalog."default" NOT NULL,
    insititucion text COLLATE pg_catalog."default",
    tipo character varying(50) COLLATE pg_catalog."default",
    reconocido_por text COLLATE pg_catalog."default",
    numero_registro character varying(50) COLLATE pg_catalog."default",
    fecha_registso date,
    area_campo text COLLATE pg_catalog."default",
    obserbacion text COLLATE pg_catalog."default",
    CONSTRAINT titulo_letrado_id_fkey FOREIGN KEY (letrado_id)
        REFERENCES sncyt.letrado (identificacion) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
)




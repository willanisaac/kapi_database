-- ============================================================================
-- ESQUEMA DE BASE DE DATOS PARA SISTEMA DE AUTENTICACIÓN JWT
-- Schema: auth
-- Propósito: Microservicio de autenticación para SPA Angular
-- Fecha: 3 de noviembre de 2025
-- ============================================================================

-- Crear el esquema
DROP SCHEMA IF EXISTS auth CASCADE;
CREATE SCHEMA auth;

-- Establecer el esquema por defecto para esta sesión
SET search_path TO auth;

-- ============================================================================
-- EXTENSIONES NECESARIAS
-- ============================================================================
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";      -- Para generar UUIDs
CREATE EXTENSION IF NOT EXISTS "pgcrypto";       -- Para encriptación adicional
CREATE EXTENSION IF NOT EXISTS "citext";         -- Para emails case-insensitive

-- ============================================================================
-- TIPOS ENUMERADOS
-- ============================================================================

-- Estado de los usuarios
DROP TYPE IF EXISTS auth.user_status CASCADE;
CREATE TYPE auth.user_status AS ENUM (
    'active',           -- Usuario activo
    'inactive',         -- Usuario inactivo temporalmente
    'suspended',        -- Usuario suspendido por violación de políticas
    'pending',          -- Pendiente de activación (verificación email)
    'locked'            -- Bloqueado por intentos fallidos
);

-- Tipos de tokens JWT
DROP TYPE IF EXISTS auth.token_type CASCADE;
CREATE TYPE auth.token_type AS ENUM (
    'access',           -- Token de acceso (corta duración)
    'refresh',          -- Token de refresco (larga duración)
    'verification',     -- Token para verificación de email
    'reset_password'    -- Token para reseteo de contraseña
);

-- Nivel de severidad de auditoría
DROP TYPE IF EXISTS auth.audit_severity CASCADE;
CREATE TYPE auth.audit_severity AS ENUM (
    'info',
    'warning',
    'error',
    'critical'
);

-- Tipo de evento de auditoría
DROP TYPE IF EXISTS auth.audit_event_type CASCADE;
CREATE TYPE auth.audit_event_type AS ENUM (
    'login_success',
    'login_failed',
    'logout',
    'token_refresh',
    'token_revoked',
    'password_changed',
    'password_reset_requested',
    'password_reset_completed',
    'email_verification',
    'account_locked',
    'account_unlocked',
    'account_suspended',
    'account_activated',
    'profile_updated',
    'permission_changed',
    'unauthorized_access_attempt'
);

-- ============================================================================
-- TABLA: users
-- Almacena la información principal de los usuarios
-- ============================================================================
DROP TABLE IF EXISTS auth.users CASCADE;
CREATE TABLE auth.users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Información de autenticación
    email CITEXT UNIQUE NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,  -- Almacena hash bcrypt/argon2
    
    -- Información personal
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    phone_number VARCHAR(20),
    
    -- Estado y seguridad
    status auth.user_status NOT NULL DEFAULT 'pending',
    email_verified BOOLEAN DEFAULT FALSE,
    email_verified_at TIMESTAMP WITH TIME ZONE,
    
    -- Control de intentos fallidos
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    
    -- Seguridad adicional
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),  -- Para TOTP (Google Authenticator, etc.)
    
    -- Control de contraseñas
    password_changed_at TIMESTAMP WITH TIME ZONE,
    must_change_password BOOLEAN DEFAULT FALSE,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP WITH TIME ZONE,
    deleted_at TIMESTAMP WITH TIME ZONE,  -- Soft delete
    
    -- Constraints
    CONSTRAINT email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT username_format CHECK (username ~* '^[a-zA-Z0-9_-]+$'),
    CONSTRAINT username_length CHECK (LENGTH(username) >= 3)
);

-- Índices para users
CREATE INDEX idx_users_email ON auth.users(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_username ON auth.users(username) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_status ON auth.users(status);
CREATE INDEX idx_users_created_at ON auth.users(created_at);

-- ============================================================================
-- TABLA: roles
-- Define los roles del sistema
-- ============================================================================
DROP TABLE IF EXISTS auth.roles CASCADE;
CREATE TABLE auth.roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    is_system_role BOOLEAN DEFAULT FALSE,  -- Roles del sistema no eliminables
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT role_name_format CHECK (name ~* '^[A-Z_]+$')
);

-- Índices para roles
CREATE INDEX idx_roles_name ON auth.roles(name);

-- ============================================================================
-- TABLA: permissions
-- Define los permisos granulares del sistema
-- ============================================================================
DROP TABLE IF EXISTS auth.permissions CASCADE;
CREATE TABLE auth.permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    resource VARCHAR(50) NOT NULL,      -- Ej: 'users', 'products', 'orders'
    action VARCHAR(50) NOT NULL,        -- Ej: 'create', 'read', 'update', 'delete'
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT permission_name_format CHECK (name ~* '^[a-z_]+\.[a-z_]+$'),
    UNIQUE(resource, action)
);

-- Índices para permissions
CREATE INDEX idx_permissions_resource ON auth.permissions(resource);
CREATE INDEX idx_permissions_action ON auth.permissions(action);

-- ============================================================================
-- TABLA: user_roles
-- Relación muchos a muchos entre usuarios y roles
-- ============================================================================
DROP TABLE IF EXISTS auth.user_roles CASCADE;
CREATE TABLE auth.user_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES auth.roles(id) ON DELETE CASCADE,
    
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_by UUID REFERENCES auth.users(id),
    expires_at TIMESTAMP WITH TIME ZONE,  -- Para roles temporales
    
    UNIQUE(user_id, role_id)
);

-- Índices para user_roles
CREATE INDEX idx_user_roles_user_id ON auth.user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON auth.user_roles(role_id);
CREATE INDEX idx_user_roles_expires_at ON auth.user_roles(expires_at) WHERE expires_at IS NOT NULL;

-- ============================================================================
-- TABLA: role_permissions
-- Relación muchos a muchos entre roles y permisos
-- ============================================================================
DROP TABLE IF EXISTS auth.role_permissions CASCADE;
CREATE TABLE auth.role_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_id UUID NOT NULL REFERENCES auth.roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES auth.permissions(id) ON DELETE CASCADE,
    
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(role_id, permission_id)
);

-- Índices para role_permissions
CREATE INDEX idx_role_permissions_role_id ON auth.role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission_id ON auth.role_permissions(permission_id);

-- ============================================================================
-- TABLA: refresh_tokens
-- Almacena tokens de refresco JWT para renovación de acceso
-- ============================================================================
DROP TABLE IF EXISTS auth.refresh_tokens CASCADE;
CREATE TABLE auth.refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    
    -- Token information
    token_hash VARCHAR(255) UNIQUE NOT NULL,  -- Hash del token para seguridad
    token_family UUID NOT NULL,  -- Para detectar token reuse (rotation)
    
    -- Metadata del dispositivo/cliente
    device_id VARCHAR(255),
    device_name VARCHAR(100),
    user_agent TEXT,
    ip_address INET,
    
    -- Geolocalización
    country VARCHAR(2),
    city VARCHAR(100),
    
    -- Control de validez
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_used_at TIMESTAMP WITH TIME ZONE,
    
    -- Estado
    is_revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_reason VARCHAR(255),
    
    -- Relación con otros tokens (para rotación)
    parent_token_id UUID REFERENCES auth.refresh_tokens(id),
    
    CONSTRAINT valid_expiration CHECK (expires_at > issued_at)
);

-- Índices para refresh_tokens
CREATE INDEX idx_refresh_tokens_user_id ON auth.refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token_hash ON auth.refresh_tokens(token_hash) WHERE NOT is_revoked;
CREATE INDEX idx_refresh_tokens_token_family ON auth.refresh_tokens(token_family);
CREATE INDEX idx_refresh_tokens_expires_at ON auth.refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_device_id ON auth.refresh_tokens(device_id);

-- ============================================================================
-- TABLA: active_sessions
-- Registra sesiones activas para control de sesiones concurrentes
-- ============================================================================
DROP TABLE IF EXISTS auth.active_sessions CASCADE;
CREATE TABLE auth.active_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    
    -- Token de sesión (JTI del access token)
    session_token VARCHAR(255) UNIQUE NOT NULL,
    refresh_token_id UUID REFERENCES auth.refresh_tokens(id) ON DELETE CASCADE,
    
    -- Información del cliente
    device_id VARCHAR(255),
    user_agent TEXT,
    ip_address INET NOT NULL,
    
    -- Geolocalización
    country VARCHAR(2),
    city VARCHAR(100),
    
    -- Control de sesión
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Estado
    is_active BOOLEAN DEFAULT TRUE,
    terminated_at TIMESTAMP WITH TIME ZONE,
    termination_reason VARCHAR(255)
);

-- Índices para active_sessions
CREATE INDEX idx_active_sessions_user_id ON auth.active_sessions(user_id) WHERE is_active;
CREATE INDEX idx_active_sessions_session_token ON auth.active_sessions(session_token) WHERE is_active;
CREATE INDEX idx_active_sessions_expires_at ON auth.active_sessions(expires_at);
CREATE INDEX idx_active_sessions_last_activity ON auth.active_sessions(last_activity_at);

-- ============================================================================
-- TABLA: blacklisted_tokens
-- Tokens JWT revocados antes de su expiración (logout, cambio password, etc)
-- ============================================================================
DROP TABLE IF EXISTS auth.blacklisted_tokens CASCADE;
CREATE TABLE auth.blacklisted_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Token information
    token_jti VARCHAR(255) UNIQUE NOT NULL,  -- JWT ID
    token_type auth.token_type NOT NULL,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    
    -- Control
    blacklisted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,  -- Cuando el token expiraría naturalmente
    reason VARCHAR(255),
    
    CONSTRAINT valid_blacklist_expiration CHECK (expires_at > blacklisted_at)
);

-- Índices para blacklisted_tokens
CREATE INDEX idx_blacklisted_tokens_jti ON auth.blacklisted_tokens(token_jti);
CREATE INDEX idx_blacklisted_tokens_user_id ON auth.blacklisted_tokens(user_id);
CREATE INDEX idx_blacklisted_tokens_expires_at ON auth.blacklisted_tokens(expires_at);

-- ============================================================================
-- TABLA: password_reset_tokens
-- Tokens para reseteo de contraseña (one-time use)
-- ============================================================================
DROP TABLE IF EXISTS auth.password_reset_tokens CASCADE;
CREATE TABLE auth.password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    
    -- Información de la solicitud
    ip_address INET,
    user_agent TEXT,
    
    CONSTRAINT valid_reset_expiration CHECK (expires_at > created_at)
);

-- Índices para password_reset_tokens
CREATE INDEX idx_password_reset_tokens_user_id ON auth.password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_token_hash ON auth.password_reset_tokens(token_hash) WHERE used_at IS NULL;
CREATE INDEX idx_password_reset_tokens_expires_at ON auth.password_reset_tokens(expires_at);

-- ============================================================================
-- TABLA: email_verification_tokens
-- Tokens para verificación de email
-- ============================================================================
DROP TABLE IF EXISTS auth.email_verification_tokens CASCADE;
CREATE TABLE auth.email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    email CITEXT NOT NULL,  -- El email a verificar
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT valid_verification_expiration CHECK (expires_at > created_at)
);

-- Índices para email_verification_tokens
CREATE INDEX idx_email_verification_tokens_user_id ON auth.email_verification_tokens(user_id);
CREATE INDEX idx_email_verification_tokens_token_hash ON auth.email_verification_tokens(token_hash) WHERE verified_at IS NULL;
CREATE INDEX idx_email_verification_tokens_expires_at ON auth.email_verification_tokens(expires_at);

-- ============================================================================
-- TABLA: audit_logs
-- Registro detallado de todas las acciones de seguridad y autenticación
-- ============================================================================
DROP TABLE IF EXISTS auth.audit_logs CASCADE;
CREATE TABLE auth.audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Actor y contexto
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    username VARCHAR(50),  -- Copia desnormalizada por si el usuario se elimina
    
    -- Evento
    event_type auth.audit_event_type NOT NULL,
    severity auth.audit_severity NOT NULL DEFAULT 'info',
    description TEXT NOT NULL,
    
    -- Detalles adicionales (JSON flexible)
    metadata JSONB,  -- Ej: cambios realizados, valores anteriores, etc.
    
    -- Información del request
    ip_address INET,
    user_agent TEXT,
    request_id VARCHAR(100),  -- Para correlación con logs de aplicación
    
    -- Geolocalización
    country VARCHAR(2),
    city VARCHAR(100),
    
    -- Resultado
    success BOOLEAN NOT NULL,
    error_message TEXT,
    
    -- Timestamp
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Índice en metadata para búsquedas
    CONSTRAINT metadata_is_object CHECK (jsonb_typeof(metadata) = 'object' OR metadata IS NULL)
);

-- Índices para audit_logs
CREATE INDEX idx_audit_logs_user_id ON auth.audit_logs(user_id);
CREATE INDEX idx_audit_logs_event_type ON auth.audit_logs(event_type);
CREATE INDEX idx_audit_logs_severity ON auth.audit_logs(severity);
CREATE INDEX idx_audit_logs_created_at ON auth.audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_ip_address ON auth.audit_logs(ip_address);
CREATE INDEX idx_audit_logs_success ON auth.audit_logs(success);
CREATE INDEX idx_audit_logs_metadata ON auth.audit_logs USING GIN(metadata);

-- ============================================================================
-- TABLA: login_history
-- Historial de intentos de login (exitosos y fallidos)
-- ============================================================================
DROP TABLE IF EXISTS auth.login_history CASCADE;
CREATE TABLE auth.login_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    email CITEXT,
    username VARCHAR(50),
    
    -- Resultado del intento
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(255),  -- 'invalid_credentials', 'account_locked', etc.
    
    -- Información del request
    ip_address INET NOT NULL,
    user_agent TEXT,
    device_id VARCHAR(255),
    
    -- Geolocalización
    country VARCHAR(2),
    city VARCHAR(100),
    
    -- Timestamp
    attempted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Índices para login_history
CREATE INDEX idx_login_history_user_id ON auth.login_history(user_id);
CREATE INDEX idx_login_history_email ON auth.login_history(email);
CREATE INDEX idx_login_history_attempted_at ON auth.login_history(attempted_at DESC);
CREATE INDEX idx_login_history_success ON auth.login_history(success);
CREATE INDEX idx_login_history_ip_address ON auth.login_history(ip_address);

-- Índice parcial para intentos fallidos recientes (útil para detección de ataques)
CREATE INDEX idx_login_history_failed_recent ON auth.login_history(email, attempted_at DESC) 
    WHERE NOT success AND attempted_at > CURRENT_TIMESTAMP - INTERVAL '1 hour';

-- ============================================================================
-- TABLA: security_settings
-- Configuración de políticas de seguridad del sistema
-- ============================================================================
DROP TABLE IF EXISTS auth.security_settings CASCADE;
CREATE TABLE auth.security_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Configuración de tokens
    access_token_lifetime_minutes INTEGER DEFAULT 15,
    refresh_token_lifetime_days INTEGER DEFAULT 30,
    password_reset_token_lifetime_minutes INTEGER DEFAULT 60,
    email_verification_token_lifetime_hours INTEGER DEFAULT 24,
    
    -- Políticas de contraseña
    password_min_length INTEGER DEFAULT 8,
    password_require_uppercase BOOLEAN DEFAULT TRUE,
    password_require_lowercase BOOLEAN DEFAULT TRUE,
    password_require_digit BOOLEAN DEFAULT TRUE,
    password_require_special_char BOOLEAN DEFAULT TRUE,
    password_expiry_days INTEGER,  -- NULL = no expira
    password_history_count INTEGER DEFAULT 5,  -- Evitar reusar últimas N contraseñas
    
    -- Políticas de bloqueo de cuenta
    max_failed_login_attempts INTEGER DEFAULT 5,
    account_lockout_duration_minutes INTEGER DEFAULT 30,
    
    -- Sesiones concurrentes
    max_concurrent_sessions INTEGER,  -- NULL = ilimitado
    
    -- 2FA
    require_2fa_for_all_users BOOLEAN DEFAULT FALSE,
    
    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID REFERENCES auth.users(id)
);

-- Solo debe haber una fila de configuración (singleton)
CREATE UNIQUE INDEX idx_security_settings_singleton ON auth.security_settings((id IS NOT NULL));

-- ============================================================================
-- TABLA: password_history
-- Historial de contraseñas para prevenir reutilización
-- ============================================================================
DROP TABLE IF EXISTS auth.password_history CASCADE;
CREATE TABLE auth.password_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Índices para password_history
CREATE INDEX idx_password_history_user_id ON auth.password_history(user_id, created_at DESC);

-- ============================================================================
-- FUNCIONES Y TRIGGERS
-- ============================================================================

-- Función para actualizar updated_at automáticamente
CREATE OR REPLACE FUNCTION auth.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers para updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON auth.users
    FOR EACH ROW EXECUTE FUNCTION auth.update_updated_at_column();

CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON auth.roles
    FOR EACH ROW EXECUTE FUNCTION auth.update_updated_at_column();

-- Función para limpiar tokens expirados (mantenimiento)
CREATE OR REPLACE FUNCTION auth.cleanup_expired_tokens()
RETURNS void AS $$
BEGIN
    -- Limpiar refresh tokens expirados
    DELETE FROM auth.refresh_tokens 
    WHERE expires_at < CURRENT_TIMESTAMP - INTERVAL '7 days';
    
    -- Limpiar tokens en blacklist que ya expiraron
    DELETE FROM auth.blacklisted_tokens 
    WHERE expires_at < CURRENT_TIMESTAMP;
    
    -- Limpiar tokens de reset usados o expirados
    DELETE FROM auth.password_reset_tokens 
    WHERE used_at IS NOT NULL OR expires_at < CURRENT_TIMESTAMP;
    
    -- Limpiar tokens de verificación usados o expirados
    DELETE FROM auth.email_verification_tokens 
    WHERE verified_at IS NOT NULL OR expires_at < CURRENT_TIMESTAMP;
    
    -- Limpiar sesiones expiradas
    UPDATE auth.active_sessions 
    SET is_active = FALSE, 
        terminated_at = CURRENT_TIMESTAMP,
        termination_reason = 'expired'
    WHERE expires_at < CURRENT_TIMESTAMP AND is_active = TRUE;
    
END;
$$ LANGUAGE plpgsql;

-- Función para registrar auditoría de login
CREATE OR REPLACE FUNCTION auth.log_login_attempt(
    p_user_id UUID,
    p_email CITEXT,
    p_username VARCHAR,
    p_success BOOLEAN,
    p_failure_reason VARCHAR,
    p_ip_address INET,
    p_user_agent TEXT
)
RETURNS void AS $$
BEGIN
    INSERT INTO auth.login_history (
        user_id, email, username, success, failure_reason, 
        ip_address, user_agent
    ) VALUES (
        p_user_id, p_email, p_username, p_success, p_failure_reason,
        p_ip_address, p_user_agent
    );
    
    -- Si el login falló, incrementar contador de intentos fallidos
    IF NOT p_success AND p_user_id IS NOT NULL THEN
        UPDATE auth.users 
        SET failed_login_attempts = failed_login_attempts + 1
        WHERE id = p_user_id;
    END IF;
    
    -- Si el login fue exitoso, resetear contador
    IF p_success AND p_user_id IS NOT NULL THEN
        UPDATE auth.users 
        SET failed_login_attempts = 0,
            last_login_at = CURRENT_TIMESTAMP,
            locked_until = NULL
        WHERE id = p_user_id;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Función para verificar si un usuario debe ser bloqueado
CREATE OR REPLACE FUNCTION auth.check_and_lock_user()
RETURNS TRIGGER AS $$
DECLARE
    v_max_attempts INTEGER;
    v_lockout_duration INTEGER;
BEGIN
    -- Obtener configuración de seguridad
    SELECT max_failed_login_attempts, account_lockout_duration_minutes
    INTO v_max_attempts, v_lockout_duration
    FROM auth.security_settings
    LIMIT 1;
    
    -- Si no hay configuración, usar valores por defecto
    v_max_attempts := COALESCE(v_max_attempts, 5);
    v_lockout_duration := COALESCE(v_lockout_duration, 30);
    
    -- Si se alcanzó el máximo de intentos, bloquear cuenta
    IF NEW.failed_login_attempts >= v_max_attempts THEN
        NEW.status := 'locked';
        NEW.locked_until := CURRENT_TIMESTAMP + (v_lockout_duration || ' minutes')::INTERVAL;
        
        -- Registrar evento de auditoría
        INSERT INTO auth.audit_logs (
            user_id, username, event_type, severity, description,
            success, metadata
        ) VALUES (
            NEW.id, NEW.username, 'account_locked', 'warning',
            'Account locked due to too many failed login attempts',
            TRUE, jsonb_build_object(
                'failed_attempts', NEW.failed_login_attempts,
                'locked_until', NEW.locked_until
            )
        );
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger para bloqueo automático
CREATE TRIGGER check_user_lock BEFORE UPDATE ON auth.users
    FOR EACH ROW 
    WHEN (NEW.failed_login_attempts > OLD.failed_login_attempts)
    EXECUTE FUNCTION auth.check_and_lock_user();

-- ============================================================================
-- VISTAS ÚTILES
-- ============================================================================

-- Vista de usuarios con sus roles
DROP VIEW IF EXISTS auth.v_user_roles CASCADE;
CREATE OR REPLACE VIEW auth.v_user_roles AS
SELECT 
    u.id AS user_id,
    u.username,
    u.email,
    u.status,
    r.id AS role_id,
    r.name AS role_name,
    ur.assigned_at,
    ur.expires_at,
    CASE 
        WHEN ur.expires_at IS NOT NULL AND ur.expires_at < CURRENT_TIMESTAMP 
        THEN TRUE 
        ELSE FALSE 
    END AS is_expired
FROM auth.users u
INNER JOIN auth.user_roles ur ON u.id = ur.user_id
INNER JOIN auth.roles r ON ur.role_id = r.id
WHERE u.deleted_at IS NULL;

-- Vista de permisos efectivos de usuario (a través de roles)
DROP VIEW IF EXISTS auth.v_user_permissions CASCADE;
CREATE OR REPLACE VIEW auth.v_user_permissions AS
SELECT DISTINCT
    u.id AS user_id,
    u.username,
    u.email,
    p.id AS permission_id,
    p.name AS permission_name,
    p.resource,
    p.action
FROM auth.users u
INNER JOIN auth.user_roles ur ON u.id = ur.user_id
INNER JOIN auth.role_permissions rp ON ur.role_id = rp.role_id
INNER JOIN auth.permissions p ON rp.permission_id = p.id
WHERE u.deleted_at IS NULL
  AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP);

-- Vista de sesiones activas con información del usuario
DROP VIEW IF EXISTS auth.v_active_sessions CASCADE;
CREATE OR REPLACE VIEW auth.v_active_sessions AS
SELECT 
    s.id AS session_id,
    s.user_id,
    u.username,
    u.email,
    s.device_id,
    s.ip_address,
    s.country,
    s.city,
    s.created_at,
    s.last_activity_at,
    s.expires_at,
    EXTRACT(EPOCH FROM (s.expires_at - CURRENT_TIMESTAMP)) / 60 AS minutes_until_expiry
FROM auth.active_sessions s
INNER JOIN auth.users u ON s.user_id = u.id
WHERE s.is_active = TRUE
  AND s.expires_at > CURRENT_TIMESTAMP;

-- Vista de estadísticas de seguridad por usuario
DROP VIEW IF EXISTS auth.v_user_security_stats CASCADE;
CREATE OR REPLACE VIEW auth.v_user_security_stats AS
SELECT 
    u.id AS user_id,
    u.username,
    u.email,
    u.status,
    u.failed_login_attempts,
    u.locked_until,
    u.two_factor_enabled,
    u.last_login_at,
    COUNT(DISTINCT s.id) AS active_sessions_count,
    COUNT(DISTINCT rt.id) AS active_refresh_tokens_count,
    (
        SELECT COUNT(*) 
        FROM auth.login_history lh 
        WHERE lh.user_id = u.id 
          AND NOT lh.success 
          AND lh.attempted_at > CURRENT_TIMESTAMP - INTERVAL '24 hours'
    ) AS failed_logins_last_24h,
    (
        SELECT MAX(attempted_at) 
        FROM auth.login_history lh 
        WHERE lh.user_id = u.id 
          AND NOT lh.success
    ) AS last_failed_login_at
FROM auth.users u
LEFT JOIN auth.active_sessions s ON u.id = s.user_id AND s.is_active = TRUE
LEFT JOIN auth.refresh_tokens rt ON u.id = rt.user_id AND NOT rt.is_revoked AND rt.expires_at > CURRENT_TIMESTAMP
WHERE u.deleted_at IS NULL
GROUP BY u.id, u.username, u.email, u.status, u.failed_login_attempts, 
         u.locked_until, u.two_factor_enabled, u.last_login_at;

-- ============================================================================
-- DATOS INICIALES
-- ============================================================================

-- Insertar configuración de seguridad por defecto
INSERT INTO auth.security_settings (
    access_token_lifetime_minutes,
    refresh_token_lifetime_days,
    password_reset_token_lifetime_minutes,
    email_verification_token_lifetime_hours,
    password_min_length,
    password_require_uppercase,
    password_require_lowercase,
    password_require_digit,
    password_require_special_char,
    password_expiry_days,
    password_history_count,
    max_failed_login_attempts,
    account_lockout_duration_minutes,
    max_concurrent_sessions,
    require_2fa_for_all_users
) VALUES (
    15,      -- Access token: 15 minutos
    30,      -- Refresh token: 30 días
    60,      -- Password reset: 60 minutos
    24,      -- Email verification: 24 horas
    8,       -- Longitud mínima de contraseña
    TRUE,    -- Requiere mayúsculas
    TRUE,    -- Requiere minúsculas
    TRUE,    -- Requiere dígitos
    TRUE,    -- Requiere caracteres especiales
    90,      -- Contraseñas expiran en 90 días
    5,       -- Recordar últimas 5 contraseñas
    5,       -- Máximo 5 intentos fallidos
    30,      -- Bloqueo por 30 minutos
    NULL,    -- Sesiones concurrentes ilimitadas
    FALSE    -- 2FA no obligatorio para todos
);

-- Crear roles básicos del sistema
INSERT INTO auth.roles (name, description, is_system_role) VALUES
    ('SUPER_ADMIN', 'Administrador con acceso total al sistema', TRUE),
    ('ADMIN', 'Administrador con permisos de gestión', TRUE),
    ('USER', 'Usuario estándar del sistema', TRUE),
    ('GUEST', 'Usuario invitado con permisos limitados', TRUE);

-- Crear permisos básicos
INSERT INTO auth.permissions (name, description, resource, action) VALUES
    -- Permisos de usuarios
    ('users.create', 'Crear nuevos usuarios', 'users', 'create'),
    ('users.read', 'Leer información de usuarios', 'users', 'read'),
    ('users.update', 'Actualizar información de usuarios', 'users', 'update'),
    ('users.delete', 'Eliminar usuarios', 'users', 'delete'),
    ('users.read_self', 'Leer propia información', 'users', 'read_self'),
    ('users.update_self', 'Actualizar propia información', 'users', 'update_self'),
    
    -- Permisos de roles
    ('roles.create', 'Crear roles', 'roles', 'create'),
    ('roles.read', 'Leer roles', 'roles', 'read'),
    ('roles.update', 'Actualizar roles', 'roles', 'update'),
    ('roles.delete', 'Eliminar roles', 'roles', 'delete'),
    
    -- Permisos de sesiones
    ('sessions.read', 'Ver sesiones activas', 'sessions', 'read'),
    ('sessions.revoke', 'Revocar sesiones', 'sessions', 'revoke'),
    ('sessions.read_self', 'Ver propias sesiones', 'sessions', 'read_self'),
    ('sessions.revoke_self', 'Revocar propias sesiones', 'sessions', 'revoke_self'),
    
    -- Permisos de auditoría
    ('audit.read', 'Leer logs de auditoría', 'audit', 'read'),
    
    -- Permisos de configuración
    ('settings.read', 'Leer configuración de seguridad', 'settings', 'read'),
    ('settings.update', 'Actualizar configuración de seguridad', 'settings', 'update');

-- Asignar permisos a roles
DO $$
DECLARE
    v_super_admin_id UUID;
    v_admin_id UUID;
    v_user_id UUID;
    v_guest_id UUID;
BEGIN
    -- Obtener IDs de roles
    SELECT id INTO v_super_admin_id FROM auth.roles WHERE name = 'SUPER_ADMIN';
    SELECT id INTO v_admin_id FROM auth.roles WHERE name = 'ADMIN';
    SELECT id INTO v_user_id FROM auth.roles WHERE name = 'USER';
    SELECT id INTO v_guest_id FROM auth.roles WHERE name = 'GUEST';
    
    -- SUPER_ADMIN: Todos los permisos
    INSERT INTO auth.role_permissions (role_id, permission_id)
    SELECT v_super_admin_id, id FROM auth.permissions;
    
    -- ADMIN: Permisos de gestión (excepto super admin)
    INSERT INTO auth.role_permissions (role_id, permission_id)
    SELECT v_admin_id, id FROM auth.permissions
    WHERE name IN (
        'users.create', 'users.read', 'users.update',
        'roles.read', 'sessions.read', 'sessions.revoke',
        'audit.read', 'settings.read'
    );
    
    -- USER: Permisos básicos
    INSERT INTO auth.role_permissions (role_id, permission_id)
    SELECT v_user_id, id FROM auth.permissions
    WHERE name IN (
        'users.read_self', 'users.update_self',
        'sessions.read_self', 'sessions.revoke_self'
    );
    
    -- GUEST: Solo lectura propia
    INSERT INTO auth.role_permissions (role_id, permission_id)
    SELECT v_guest_id, id FROM auth.permissions
    WHERE name IN ('users.read_self');
END $$;

-- ============================================================================
-- COMENTARIOS EN TABLAS (DOCUMENTACIÓN)
-- ============================================================================

COMMENT ON SCHEMA auth IS 'Esquema para sistema de autenticación JWT con soporte para microservicios';

COMMENT ON TABLE auth.users IS 'Tabla principal de usuarios del sistema';
COMMENT ON TABLE auth.roles IS 'Roles para control de acceso basado en roles (RBAC)';
COMMENT ON TABLE auth.permissions IS 'Permisos granulares del sistema';
COMMENT ON TABLE auth.refresh_tokens IS 'Tokens de refresco JWT con rotación y detección de reuso';
COMMENT ON TABLE auth.active_sessions IS 'Sesiones activas para control de concurrencia';
COMMENT ON TABLE auth.blacklisted_tokens IS 'Tokens JWT revocados antes de su expiración natural';
COMMENT ON TABLE auth.audit_logs IS 'Registro completo de auditoría de eventos de seguridad';
COMMENT ON TABLE auth.login_history IS 'Historial de intentos de login para análisis de seguridad';
COMMENT ON TABLE auth.security_settings IS 'Configuración centralizada de políticas de seguridad';

-- ============================================================================
-- FIN DEL ESQUEMA
-- ============================================================================

-- Para verificar la instalación:
-- SELECT table_name FROM information_schema.tables WHERE table_schema = 'auth';
-- SELECT routine_name FROM information_schema.routines WHERE routine_schema = 'auth';

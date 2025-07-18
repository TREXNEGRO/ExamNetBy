/**
 * Controlador para la gestión segura de perfiles de usuario,
 * mitigando vulnerabilidades de Insecure Direct Object Reference (IDOR).
 * 
 * Requiere que un middleware de autenticación haya poblado `req.user`
 * con la información del usuario autenticado.
 */

const express = require('express');
const router = express.Router();

/**
 * Middleware de autorización para validar acceso a perfiles.
 * Solo permite acceso si:
 *  - El usuario solicita su propio perfil, o
 *  - Tiene permisos explícitos para acceder a perfiles de terceros.
 * 
 * @param {Request} req
 * @param {Response} res
 * @param {Function} next
 */
async function authorizeUserAccess(req, res, next) {
  try {
    const authenticatedUserId = req.user?.id;
    const requestedUserId = req.params.id;

    // Validación estricta: si hay un parámetro ID, validar que sea el mismo usuario o permiso especial.
    if (requestedUserId && requestedUserId !== authenticatedUserId) {
      // Aquí puedes implementar lógica para roles o permisos especiales, p.ej. admin.
      const hasPermission = await checkUserPermission(authenticatedUserId, requestedUserId);
      if (!hasPermission) {
        return res.status(403).json({ error: 'Acceso denegado: sin permisos para este recurso.' });
      }
    }
    // Si no hay ID o acceso permitido, continúa el flujo
    next();
  } catch (error) {
    console.error('[authorizeUserAccess] Error inesperado:', error);
    return res.status(500).json({ error: 'Error interno en la validación de acceso.' });
  }
}

/**
 * Endpoint seguro para obtener el perfil del usuario autenticado.
 * No acepta parámetros, siempre devuelve la información del usuario en sesión.
 */
router.get('/profile', async (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ error: 'Usuario no autenticado.' });
    }

    const user = await db.findUserById(userId);
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado.' });
    }

    // Exponer solo los campos necesarios y seguros
    const safeUserData = {
      name: user.name,
      color: user.color,
      size: user.size
    };

    res.status(200).json(safeUserData);
  } catch (error) {
    console.error('[GET /profile] Error al obtener perfil:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

/**
 * Endpoint para obtener perfiles específicos, solo si el usuario tiene permisos.
 * Aplica el middleware authorizeUserAccess para control estricto de acceso.
 */
router.get('/profile/:id', authorizeUserAccess, async (req, res) => {
  try {
    const requestedUserId = req.params.id;

    const user = await db.findUserById(requestedUserId);
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado.' });
    }

    // De nuevo, exponer solo datos necesarios, evitar sobreexposición
    const safeUserData = {
      name: user.name,
      color: user.color,
      size: user.size
    };

    res.status(200).json(safeUserData);
  } catch (error) {
    console.error(`[GET /profile/${req.params.id}] Error al obtener perfil:`, error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

/**
 * Función ficticia para validar permisos de acceso a perfiles de terceros.
 * Debe implementar la lógica de negocio según roles, jerarquías o reglas específicas.
 * 
 * @param {string} authenticatedUserId - ID del usuario autenticado
 * @param {string} targetUserId - ID del perfil solicitado
 * @returns {Promise<boolean>} true si tiene permiso, false si no
 */
async function checkUserPermission(authenticatedUserId, targetUserId) {
  // Ejemplo simplificado:
  // Retornar true si es admin o si está explícitamente autorizado (ejemplo estático)
  if (authenticatedUserId === 'admin') return true;

  // Aquí agregar lógica de consulta a DB para permisos específicos
  return false;
}

module.exports = router;

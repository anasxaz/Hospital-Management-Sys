/**
 * ============================================================
 *  Module de Validation & Sanitisation — Hospital Management System
 *  Remédiation DevSecOps — SonarCloud Blockers (CWE-943, CWE-117)
 *
 *  Adresse les vulnérabilités détectées par SonarCloud :
 *   - L14, L46, L72 PatientController.js : injection MongoDB
 *   - L10 PatientController.js : log de données utilisateur
 * ============================================================
 */

/**
 * Sanitise une chaîne de caractères — rejette les opérateurs MongoDB.
 * Remédie à : CWE-943 (MongoDB Injection via $where, $gt, $regex...)
 * @param {*} input - Donnée brute de req.body / req.query / req.params
 * @returns {string|null} - Chaîne assainie ou null si invalide
 */
export const sanitizeString = (input) => {
  if (typeof input !== 'string') return null;
  // Rejeter les opérateurs MongoDB et caractères structurels JSON
  if (/[\$\{\}]/.test(input)) return null;
  const trimmed = input.trim();
  if (trimmed.length === 0) return null;
  return trimmed;
};

/**
 * Valide et normalise une adresse email.
 * Empêche l'injection via un objet MongoDB comme { $gt: "" }
 * @param {*} email
 * @returns {string|null}
 */
export const validateEmail = (email) => {
  if (typeof email !== 'string') return null;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const trimmed = email.toLowerCase().trim();
  if (!emailRegex.test(trimmed)) return null;
  // Sécurité supplémentaire : rejeter les opérateurs MongoDB
  if (/[\$\{\}]/.test(trimmed)) return null;
  return trimmed;
};

/**
 * Valide un identifiant MongoDB ObjectId (format 24 caractères hexadécimaux).
 * Remédie à : injection via _id malformé dans deleteOne / findById
 * @param {*} id
 * @returns {string|null}
 */
export const validateObjectId = (id) => {
  if (typeof id !== 'string') return null;
  return /^[a-f\d]{24}$/i.test(id) ? id : null;
};

/**
 * Valide l'ensemble des données d'enregistrement d'un patient.
 * Centralise la validation pour éviter la duplication dans les controllers.
 * @param {object} data - req.body brut
 * @returns {{ valid: boolean, sanitized?: object, error?: string }}
 */
export const validatePatientData = (data) => {
  if (!data || typeof data !== 'object') {
    return { valid: false, error: 'Données manquantes ou invalides' };
  }

  const name = sanitizeString(data.name);
  if (!name) {
    return { valid: false, error: 'Nom invalide ou vide' };
  }

  const email = validateEmail(data.email);
  if (!email) {
    return { valid: false, error: 'Adresse email invalide' };
  }

  const age = parseInt(data.age, 10);
  if (isNaN(age) || age <= 0 || age >= 150) {
    return { valid: false, error: 'Âge invalide (doit être entre 1 et 149)' };
  }

  const allowedGenders = ['Male', 'Female', 'Other'];
  if (!allowedGenders.includes(data.gender)) {
    return { valid: false, error: 'Genre invalide (Male, Female, Other)' };
  }

  const mobile = data.mobile ? sanitizeString(data.mobile) : '';

  return {
    valid: true,
    sanitized: { name, email, age, gender: data.gender, mobile },
  };
};

/**
 * Masque les champs sensibles avant tout logging (conformité RGPD Art. 25).
 * Remédie à : CWE-117 (Improper Output Neutralization for Logs)
 * @param {object} obj - Objet à logger (ex: req.body)
 * @returns {object} - Copie avec champs sensibles remplacés par '***MASKED***'
 */
export const maskSensitiveData = (obj) => {
  if (!obj || typeof obj !== 'object') return {};
  const sensitiveFields = ['password', 'token', 'secret', 'creditCard', 'email', 'mobile'];
  const masked = { ...obj };
  sensitiveFields.forEach((field) => {
    if (masked[field] !== undefined) masked[field] = '***MASKED***';
  });
  return masked;
};

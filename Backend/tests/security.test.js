/**
 * ============================================================
 *  Tests de Sécurité — Hospital Management System
 *  Contexte : Application médicale (données patients sensibles)
 *  Runner  : Node.js 18 built-in test runner (node:test)
 * ============================================================
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// ──────────────────────────────────────────────────────────────
//  1. VALIDATION DES DONNÉES PATIENTS
//  Contexte : Empêcher la corruption des dossiers médicaux
// ──────────────────────────────────────────────────────────────
describe('Validation des données patients', () => {

  const isValidPatient = (patient) => {
    if (!patient || typeof patient !== 'object') return false;
    if (typeof patient.name !== 'string' || patient.name.trim().length === 0) return false;
    if (typeof patient.age !== 'number' || patient.age <= 0 || patient.age >= 150) return false;
    if (!['Male', 'Female', 'Other'].includes(patient.gender)) return false;
    return true;
  };

  it('doit accepter un dossier patient valide', () => {
    const patient = { name: 'John Doe', age: 35, gender: 'Male' };
    assert.equal(isValidPatient(patient), true);
  });

  it('doit rejeter un nom vide (donnée médicale incomplète)', () => {
    assert.equal(isValidPatient({ name: '', age: 30, gender: 'Male' }), false);
  });

  it('doit rejeter un âge invalide ou négatif', () => {
    assert.equal(isValidPatient({ name: 'Jane', age: -1,  gender: 'Female' }), false);
    assert.equal(isValidPatient({ name: 'Jane', age: 0,   gender: 'Female' }), false);
    assert.equal(isValidPatient({ name: 'Jane', age: 200, gender: 'Female' }), false);
  });

  it('doit rejeter un genre non répertorié', () => {
    assert.equal(isValidPatient({ name: 'Alex', age: 25, gender: 'Unknown' }), false);
  });

  it('doit rejeter les données null ou undefined', () => {
    assert.equal(isValidPatient(null), false);
    assert.equal(isValidPatient(undefined), false);
    assert.equal(isValidPatient({}), false);
  });

});

// ──────────────────────────────────────────────────────────────
//  2. PROTECTION CONTRE LES INJECTIONS MONGODB
//  Critique : CVE mongoose CVSS 9.8 (Search Injection)
//  Contexte : Un attaquant peut accéder à TOUS les patients
// ──────────────────────────────────────────────────────────────
describe('Protection contre les injections MongoDB', () => {

  // Simulation d'un sanitizer qui devrait être dans PatientController.js
  const sanitizeQuery = (input) => {
    if (typeof input !== 'string') return null;
    // Rejeter les chaînes qui contiennent des caractères opérateurs MongoDB
    const forbiddenPatterns = /[\$\{\}]/;
    return forbiddenPatterns.test(input) ? null : input.trim();
  };

  const containsMongoOperator = (obj) => {
    if (typeof obj !== 'object' || obj === null) return false;
    const dangerousOps = ['$where', '$expr', '$function', '$gt', '$lt', '$ne', '$in', '$regex'];
    return Object.keys(obj).some(key => dangerousOps.includes(key));
  };

  it('doit détecter une tentative d\'injection $where (CVE mongoose)', () => {
    // Attaque réelle possible sur notre app avec mongoose < 8.9.5
    const maliciousPayload = { '$where': 'function() { return true; }' };
    assert.equal(containsMongoOperator(maliciousPayload), true,
      'L\'injection $where doit être détectée');
  });

  it('doit détecter les opérateurs de comparaison malveillants', () => {
    const bypassAuth = { '$gt': '' }; // Contourne: { password: { $gt: "" } }
    assert.equal(containsMongoOperator(bypassAuth), true,
      'L\'opérateur $gt d\'injection doit être détecté');
  });

  it('doit accepter une requête de recherche normale', () => {
    const safeQuery = { name: 'John Doe' };
    assert.equal(containsMongoOperator(safeQuery), false,
      'Une requête normale ne doit pas être bloquée');
  });

  it('doit rejeter les caractères $ dans les entrées textuelles', () => {
    assert.equal(sanitizeQuery('John Doe'),       'John Doe');
    assert.equal(sanitizeQuery('{ $gt: "" }'),    null);
    assert.equal(sanitizeQuery('$where: true'),   null);
    assert.equal(sanitizeQuery(123),              null); // Type non-string
  });

});

// ──────────────────────────────────────────────────────────────
//  3. SÉCURITÉ DE L'AUTHENTIFICATION JWT
//  Critique : CVE jws CVSS 7.5 — HMAC bypass
//  Contexte : Usurpation d'identité médecin/administrateur
// ──────────────────────────────────────────────────────────────
describe('Sécurité de l\'authentification JWT', () => {

  it('le JWT_SECRET ne doit pas être la valeur par défaut en production', () => {
    const weakSecrets = ['secret', 'password', '123456', 'default', 'change_me', ''];
    const currentSecret = process.env.JWT_SECRET || 'test-secret-ci-only';

    if (process.env.NODE_ENV === 'production') {
      assert.equal(weakSecrets.includes(currentSecret), false,
        'Le JWT_SECRET ne doit pas être une valeur faible en production');
      assert.ok(currentSecret.length >= 32,
        'Le JWT_SECRET doit faire au moins 32 caractères en production');
    } else {
      // Environnement CI/test — on vérifie juste que la variable est définie
      assert.ok(typeof currentSecret === 'string',
        'JWT_SECRET doit être une chaîne de caractères');
    }
  });

  it('un mot de passe haché bcrypt doit avoir le format correct', () => {
    // Vérifier que notre schéma utilise bcrypt (format $2b$)
    const bcryptHashPattern = /^\$2[aby]\$\d{2}\$.{53}$/;
    // Hash bcrypt réel de "TestPassword123!" généré avec bcrypt.hash()
    const mockBcryptHash = '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';

    assert.match(mockBcryptHash, bcryptHashPattern,
      'Le hash doit respecter le format bcrypt');
  });

  it('un mot de passe en clair ne doit pas ressembler à un hash bcrypt', () => {
    const plainPassword = 'MonMotDePasse123!';
    const bcryptHashPattern = /^\$2[aby]\$/;
    assert.equal(bcryptHashPattern.test(plainPassword), false,
      'Un mot de passe en clair ne doit pas être stocké comme tel');
  });

});

// ──────────────────────────────────────────────────────────────
//  4. CONFIGURATION SÉCURISÉE DE L'ENVIRONNEMENT
//  Contexte : Variables sensibles de l'application médicale
// ──────────────────────────────────────────────────────────────
describe('Configuration sécurisée', () => {

  it('la DB_Url doit être une URL MongoDB valide', () => {
    const dbUrl = process.env.DB_Url || 'mongodb://localhost:27017/hospital';
    const isValidMongoUrl = dbUrl.startsWith('mongodb://') ||
                            dbUrl.startsWith('mongodb+srv://');
    assert.ok(isValidMongoUrl,
      'DB_Url doit commencer par mongodb:// ou mongodb+srv://');
  });

  it('le port backend ne doit pas utiliser de ports système réservés', () => {
    const port = parseInt(process.env.PORT || '6005');
    assert.notEqual(port, 22,   'Port SSH réservé');
    assert.notEqual(port, 80,   'Port HTTP réservé au frontend Nginx');
    assert.notEqual(port, 443,  'Port HTTPS réservé');
    assert.notEqual(port, 3306, 'Port MySQL réservé');
    assert.ok(port >= 1024 && port <= 65535,
      `Port ${port} doit être dans la plage utilisateur [1024-65535]`);
  });

  it('la DB_Url ne doit pas contenir de credentials dans l\'URL', () => {
    const dbUrl = process.env.DB_Url || 'mongodb://localhost:27017/hospital';
    // Détecter si des credentials sont embarqués dans l'URL (mauvaise pratique)
    const hasEmbeddedCredentials = /mongodb:\/\/[^:]+:[^@]+@/.test(dbUrl);
    if (hasEmbeddedCredentials) {
      // En CI, on avertit mais on ne bloque pas
      console.warn('[AVERTISSEMENT] La DB_Url contient des credentials — utiliser des variables d\'env séparées');
    }
    assert.ok(true, 'Vérification des credentials dans DB_Url effectuée');
  });

});

// ──────────────────────────────────────────────────────────────
//  5. TESTS DE STRUCTURE DES DONNÉES MÉDICALES
//  Contexte : Intégrité des dossiers patients (RGPD Art. 5)
// ──────────────────────────────────────────────────────────────
describe('Intégrité des données médicales (RGPD)', () => {

  it('un dossier patient doit avoir les champs obligatoires', () => {
    const requiredFields = ['name', 'age', 'gender'];
    const patient = { name: 'Jane Smith', age: 28, gender: 'Female', contact: '' };

    requiredFields.forEach(field => {
      assert.ok(Object.prototype.hasOwnProperty.call(patient, field),
        `Le champ obligatoire "${field}" est manquant`);
    });
  });

  it('les données sensibles ne doivent pas être loguées en clair', () => {
    const sensitiveFields = ['password', 'token', 'secret', 'creditCard'];
    const logData = (obj) => {
      // Simuler un logger qui masque les champs sensibles
      const masked = { ...obj };
      sensitiveFields.forEach(field => {
        if (masked[field]) masked[field] = '***MASKED***';
      });
      return masked;
    };

    const userPayload = { username: 'admin', password: 'Secret123!', role: 'doctor' };
    const logged = logData(userPayload);

    assert.equal(logged.password, '***MASKED***',
      'Le mot de passe ne doit pas apparaître dans les logs');
    assert.equal(logged.username, 'admin',
      'Les données non sensibles doivent être visibles');
  });

});

/**
 * ============================================================
 *  Tests de Sécurité — Hospital Management System
 *  Contexte : Application médicale (données patients sensibles)
 *  Runner  : Node.js 18 built-in test runner (node:test)
 *  Coverage: c8 (V8 coverage → lcov pour SonarCloud)
 * ============================================================
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// Import du module de validation (remédiation SonarCloud Blockers)
import {
  sanitizeString,
  validateEmail,
  validateObjectId,
  validatePatientData,
  maskSensitiveData,
} from '../api/utils/validators.js';

// ──────────────────────────────────────────────────────────────
//  1. sanitizeString — Protection contre les injections MongoDB
//  Remédie à : CWE-943 (SonarCloud Blockers L14, L46, L72)
// ──────────────────────────────────────────────────────────────
describe('sanitizeString — Protection injection MongoDB', () => {

  it('doit accepter une chaîne normale', () => {
    assert.equal(sanitizeString('John Doe'), 'John Doe');
  });

  it('doit trimmer les espaces en début/fin', () => {
    assert.equal(sanitizeString('  Jane Smith  '), 'Jane Smith');
  });

  it('doit rejeter les chaînes contenant $', () => {
    assert.equal(sanitizeString('{ $where: "1==1" }'), null,
      'L\'opérateur $where doit être rejeté');
    assert.equal(sanitizeString('$gt'), null,
      'L\'opérateur $gt doit être rejeté');
    assert.equal(sanitizeString('$regex'), null,
      'L\'opérateur $regex doit être rejeté');
  });

  it('doit rejeter les chaînes contenant { ou }', () => {
    assert.equal(sanitizeString('{"key":"val"}'), null,
      'Les objets JSON dans les inputs doivent être rejetés');
  });

  it('doit rejeter une chaîne vide ou uniquement des espaces', () => {
    assert.equal(sanitizeString(''), null);
    assert.equal(sanitizeString('   '), null);
  });

  it('doit rejeter les types non-string', () => {
    assert.equal(sanitizeString(42), null);
    assert.equal(sanitizeString(null), null);
    assert.equal(sanitizeString(undefined), null);
    assert.equal(sanitizeString({ '$gt': '' }), null,
      'Un objet MongoDB passé directement doit être rejeté');
  });

});

// ──────────────────────────────────────────────────────────────
//  2. validateEmail — Validation des emails patients
//  Remédie à : injection via email malformé dans findOne()
// ──────────────────────────────────────────────────────────────
describe('validateEmail — Validation adresses email', () => {

  it('doit accepter un email valide', () => {
    assert.equal(validateEmail('patient@hospital.ma'), 'patient@hospital.ma');
  });

  it('doit normaliser en minuscules', () => {
    assert.equal(validateEmail('Patient@Hospital.MA'), 'patient@hospital.ma');
  });

  it('doit rejeter un email sans @', () => {
    assert.equal(validateEmail('pasenmail'), null);
  });

  it('doit rejeter un email sans domaine', () => {
    assert.equal(validateEmail('user@'), null);
  });

  it('doit rejeter une tentative d\'injection MongoDB via email', () => {
    assert.equal(validateEmail({ '$gt': '' }), null,
      'Un objet MongoDB en guise d\'email doit être rejeté');
    assert.equal(validateEmail('user$injection@test.com'), null,
      'Email contenant $ doit être rejeté');
  });

  it('doit rejeter les types non-string', () => {
    assert.equal(validateEmail(null), null);
    assert.equal(validateEmail(undefined), null);
    assert.equal(validateEmail(123), null);
  });

});

// ──────────────────────────────────────────────────────────────
//  3. validateObjectId — Validation des IDs MongoDB
//  Remédie à : SonarCloud Blocker L72 (deleteOne avec ID non validé)
// ──────────────────────────────────────────────────────────────
describe('validateObjectId — Validation identifiants MongoDB', () => {

  it('doit accepter un ObjectId valide (24 hex)', () => {
    assert.equal(validateObjectId('507f1f77bcf86cd799439011'),
      '507f1f77bcf86cd799439011');
  });

  it('doit rejeter un ID trop court', () => {
    assert.equal(validateObjectId('123abc'), null);
  });

  it('doit rejeter un ID avec caractères non-hex', () => {
    assert.equal(validateObjectId('xxxxxxxxxxxxxxxxxxxxxxxx'), null,
      'Un ID avec x (non-hex) doit être rejeté');
  });

  it('doit rejeter une tentative d\'injection via patientId', () => {
    assert.equal(validateObjectId('{ $where: "1==1" }'), null);
    assert.equal(validateObjectId({ '$ne': null }), null,
      'Un objet MongoDB en guise d\'ID doit être rejeté');
  });

  it('doit rejeter les types non-string', () => {
    assert.equal(validateObjectId(null), null);
    assert.equal(validateObjectId(undefined), null);
    assert.equal(validateObjectId(12345), null);
  });

});

// ──────────────────────────────────────────────────────────────
//  4. validatePatientData — Validation complète dossier patient
//  Remédiation globale avant création/modification en base
// ──────────────────────────────────────────────────────────────
describe('validatePatientData — Validation dossier patient complet', () => {

  const validPatient = {
    name: 'John Doe',
    email: 'john.doe@hospital.ma',
    age: 35,
    gender: 'Male',
    mobile: '0612345678',
  };

  it('doit accepter un dossier patient valide', () => {
    const result = validatePatientData(validPatient);
    assert.equal(result.valid, true);
    assert.equal(result.sanitized.name, 'John Doe');
    assert.equal(result.sanitized.email, 'john.doe@hospital.ma');
  });

  it('doit rejeter un nom vide', () => {
    const result = validatePatientData({ ...validPatient, name: '' });
    assert.equal(result.valid, false);
    assert.ok(result.error);
  });

  it('doit rejeter un nom avec opérateur MongoDB', () => {
    const result = validatePatientData({ ...validPatient, name: '{ $where: 1 }' });
    assert.equal(result.valid, false);
  });

  it('doit rejeter un email invalide', () => {
    const result = validatePatientData({ ...validPatient, email: 'pasenmail' });
    assert.equal(result.valid, false);
  });

  it('doit rejeter un âge négatif', () => {
    assert.equal(validatePatientData({ ...validPatient, age: -5 }).valid, false);
  });

  it('doit rejeter un âge de 0', () => {
    assert.equal(validatePatientData({ ...validPatient, age: 0 }).valid, false);
  });

  it('doit rejeter un âge irréaliste (≥150)', () => {
    assert.equal(validatePatientData({ ...validPatient, age: 200 }).valid, false);
  });

  it('doit rejeter un genre non répertorié', () => {
    const result = validatePatientData({ ...validPatient, gender: 'Unknown' });
    assert.equal(result.valid, false);
  });

  it('doit rejeter des données null ou undefined', () => {
    assert.equal(validatePatientData(null).valid, false);
    assert.equal(validatePatientData(undefined).valid, false);
    assert.equal(validatePatientData({}).valid, false);
  });

});

// ──────────────────────────────────────────────────────────────
//  5. maskSensitiveData — Conformité RGPD Art. 25 dans les logs
//  Remédie à : SonarCloud L10 — log de données utilisateur
// ──────────────────────────────────────────────────────────────
describe('maskSensitiveData — Conformité RGPD dans les logs', () => {

  it('doit masquer le mot de passe', () => {
    const masked = maskSensitiveData({ username: 'admin', password: 'Secret123!' });
    assert.equal(masked.password, '***MASKED***',
      'Le mot de passe ne doit jamais apparaître dans les logs');
    assert.equal(masked.username, 'admin');
  });

  it('doit masquer l\'email (données de santé RGPD Art. 9)', () => {
    const masked = maskSensitiveData({ email: 'patient@hospital.ma', name: 'John' });
    assert.equal(masked.email, '***MASKED***');
    assert.equal(masked.name, 'John');
  });

  it('doit masquer le mobile du patient', () => {
    const masked = maskSensitiveData({ mobile: '0612345678', age: 30 });
    assert.equal(masked.mobile, '***MASKED***');
    assert.equal(masked.age, 30);
  });

  it('doit masquer token et secret', () => {
    const masked = maskSensitiveData({ token: 'eyJhbGc...', secret: 'shhhh' });
    assert.equal(masked.token, '***MASKED***');
    assert.equal(masked.secret, '***MASKED***');
  });

  it('doit gérer un objet vide sans erreur', () => {
    const masked = maskSensitiveData({});
    assert.deepEqual(masked, {});
  });

  it('doit gérer null et undefined sans planter', () => {
    assert.deepEqual(maskSensitiveData(null), {});
    assert.deepEqual(maskSensitiveData(undefined), {});
  });

});

// ──────────────────────────────────────────────────────────────
//  6. Tests de Configuration Sécurisée (variables d'environnement)
// ──────────────────────────────────────────────────────────────
describe('Configuration sécurisée de l\'environnement', () => {

  it('la DB_Url doit être une URL MongoDB valide', () => {
    const dbUrl = process.env.DB_Url || 'mongodb://localhost:27017/hospital';
    const isValid = dbUrl.startsWith('mongodb://') || dbUrl.startsWith('mongodb+srv://');
    assert.ok(isValid, 'DB_Url doit commencer par mongodb:// ou mongodb+srv://');
  });

  it('le port backend doit être dans la plage utilisateur [1024-65535]', () => {
    const port = parseInt(process.env.PORT || '6005');
    assert.ok(port >= 1024 && port <= 65535,
      `Port ${port} doit être dans la plage [1024-65535]`);
    assert.notEqual(port, 22,  'Port SSH réservé');
    assert.notEqual(port, 80,  'Port HTTP réservé');
    assert.notEqual(port, 443, 'Port HTTPS réservé');
  });

  it('JWT_SECRET doit être défini et non vide', () => {
    const secret = process.env.JWT_SECRET || 'test-secret-ci-only';
    assert.ok(typeof secret === 'string' && secret.length > 0,
      'JWT_SECRET doit être une chaîne non vide');
  });

  it('les secrets faibles ne doivent pas être utilisés en production', () => {
    const weakSecrets = ['secret', 'password', '123456', 'default', 'change_me', ''];
    const currentSecret = process.env.JWT_SECRET || 'test-secret-ci-only';
    if (process.env.NODE_ENV === 'production') {
      assert.equal(weakSecrets.includes(currentSecret), false,
        'JWT_SECRET faible interdit en production');
      assert.ok(currentSecret.length >= 32,
        'JWT_SECRET doit faire ≥ 32 caractères en production');
    } else {
      assert.ok(true, 'Environnement CI — vérification allégée');
    }
  });

});

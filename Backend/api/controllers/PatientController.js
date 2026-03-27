// controllers/PatientController.js
import { Patient } from "../models/Patient.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import {
  sanitizeString,
  validateEmail,
  validateObjectId,
  validatePatientData,
  maskSensitiveData,
} from "../utils/validators.js";

// Register a new patient
export const registerPatient = async (req, res) => {
  try {
    // FIX L10 (SonarCloud) : ne pas logger les données utilisateur brutes (RGPD Art. 25 / CWE-117)
    console.log("Request received: registerPatient", maskSensitiveData(req.body));

    // FIX L14 (SonarCloud Blocker) : valider et sanitiser avant toute requête MongoDB (CWE-943)
    const validation = validatePatientData(req.body);
    if (!validation.valid) {
      return res.status(400).json({ message: validation.error });
    }

    const { name, email, age, gender, mobile } = validation.sanitized;

    // email est maintenant validé — pas d'injection possible
    const existingPatient = await Patient.findOne({ email });
    if (existingPatient) {
      return res.status(400).json({ message: "Patient already exists" });
    }

    const newPatient = await Patient.create({
      name,
      email,
      gender,
      mobile,
      age,
      patientId: uuidv4(),
    });

    res.status(201).json({ message: "Patient registered successfully", newPatient });
  } catch (error) {
    // Ne pas exposer les détails d'erreur interne
    console.error("Error registering patient");
    res.status(500).json({ message: "Server error" });
  }
};

export const getAllPatients = async (req, res) => {
  const patients = await Patient.find();
  return res.status(200).json({ data: patients });
};

// Login a patient
export const loginPatient = async (req, res) => {
  try {
    // FIX L46 (SonarCloud Blocker) : valider l'email avant la requête MongoDB (CWE-943)
    const email = validateEmail(req.body?.email);
    if (!email) {
      return res.status(400).json({ message: "Email invalide" });
    }

    const patient = await Patient.findOne({ email });
    if (!patient) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Sanitiser le mot de passe (chaîne simple, pas d'opérateurs MongoDB)
    const password = sanitizeString(req.body?.password);
    if (!password) {
      return res.status(400).json({ message: "Mot de passe invalide" });
    }

    const isMatch = await bcrypt.compare(password, patient.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: patient._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.status(200).json({ token });
  } catch (error) {
    console.error("Login error");
    res.status(500).json({ message: "Server error" });
  }
};

export const deletePatient = async (req, res) => {
  // FIX L72 (SonarCloud Blocker) : valider l'ObjectId MongoDB avant deleteOne (CWE-943)
  const patientId = validateObjectId(req.body?.patientId);
  if (!patientId) {
    return res.status(400).json({
      success: false,
      message: "ID patient invalide (format ObjectId requis)",
    });
  }

  const result = await Patient.deleteOne({ _id: patientId });

  if (!result || result.deletedCount === 0) {
    return res.status(404).json({
      success: false,
      message: "Patient not found",
    });
  }

  return res.status(200).json({ success: true, message: "Patient deleted successfully" });
};

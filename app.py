from flask import Flask, request, jsonify
from flask_cors import CORS
from functools import wraps
import jwt
import bcrypt
from datetime import datetime, timedelta
from supabase import create_client
import os
from dotenv import load_dotenv
import logging

# Charger les variables d'environnement
load_dotenv(dotenv_path="ex.env")

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}) #autorise toutes les origines
# Configuration
SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
JWT_SECRET = os.getenv('JWT_SECRET', 'hospital_jwt_secret_2024')
JWT_EXPIRES_HOURS = 168  # 7 jours

# Supabase
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')

# Admin initial (CHANGEZ CES VALEURS EN PRODUCTION)
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@hospital.com')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'Admin123!')
ADMIN_NAME = os.getenv('ADMIN_NAME', 'Administrateur Principal')

# Initialiser Supabase
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =====================================================
# UTILITAIRES
# =====================================================

def hash_password(password):
    """Hasher un mot de passe"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def check_password(password, hashed):
    """Vérifier un mot de passe hashé"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_token(user_data):
    """Générer un token JWT"""
    payload = {
        'user_id': user_data['id'],
        'email': user_data['email'],
        'role': user_data['role'],
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRES_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_token(token):
    """Vérifier un token JWT"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def token_required(f):
    """Décorateur pour vérifier le token JWT"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Vérifier dans les headers
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'message': 'Token manquant'}), 401
        
        # Vérifier le token
        payload = verify_token(token)
        if not payload:
            return jsonify({'message': 'Token invalide ou expiré'}), 401
        
        # Ajouter les infos utilisateur à la requête
        request.user = payload
        
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Décorateur pour vérifier les droits admin"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, 'user') or request.user.get('role') != 'admin':
            return jsonify({'message': 'Accès refusé. Admin requis.'}), 403
        return f(*args, **kwargs)
    return decorated

# =====================================================
# INITIALISATION DE LA BASE DE DONNÉES
# =====================================================

def init_database():
    """Initialiser les tables dans Supabase"""
    try:
        logger.info("Initialisation de la base de données...")
        
        # Vérifier/Créer la table users
        users_table_sql = """
        CREATE TABLE IF NOT EXISTS users (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            nom VARCHAR(255) NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL CHECK (role IN ('accueil', 'docteur', 'medecin', 'pharmacie', 'facturation', 'admin')),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        """
        
        # Vérifier/Créer la table patients
        patients_table_sql = """
        CREATE TABLE IF NOT EXISTS patients (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            nom_complet VARCHAR(255) NOT NULL,
            date_naissance DATE NOT NULL,
            telephone VARCHAR(50),
            email VARCHAR(255),
            adresse TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            created_by UUID REFERENCES users(id)
        );
        """
        
        # Créer les tables
        supabase.rpc('exec_sql', {'query': users_table_sql}).execute()
        supabase.rpc('exec_sql', {'query': patients_table_sql}).execute()
        
        # Créer l'admin s'il n'existe pas
        existing_admin = supabase.from_('users').select('*').eq('email', ADMIN_EMAIL).execute()
        
        if not existing_admin.data:
            admin_data = {
                'email': ADMIN_EMAIL,
                'nom': ADMIN_NAME,
                'password_hash': hash_password(ADMIN_PASSWORD),
                'role': 'admin'
            }
            supabase.from_('users').insert(admin_data).execute()
            logger.info("Compte admin créé avec succès")
        else:
            logger.info("Compte admin déjà existant")
        
        logger.info("Base de données initialisée avec succès")
        return True
        
    except Exception as e:
        logger.error(f"Erreur initialisation base de données: {e}")
        return False

# =====================================================
# ROUTES D'AUTHENTIFICATION
# =====================================================

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Enregistrer un nouvel utilisateur"""
    try:
        data = request.get_json()
        
        # Validation
        required_fields = ['nom', 'email', 'password', 'role']
        for field in required_fields:
            if field not in data:
                return jsonify({'message': f'Champ {field} manquant'}), 400
        
        # Empêcher la création d'autres admins
        if data['role'] == 'admin':
            return jsonify({'message': 'Création de compte admin non autorisée'}), 403
        
        # Vérifier si l'email existe déjà
        existing_user = supabase.from_('users').select('*').eq('email', data['email']).execute()
        if existing_user.data:
            return jsonify({'message': 'Email déjà utilisé'}), 409
        
        # Créer l'utilisateur
        user_data = {
            'nom': data['nom'],
            'email': data['email'],
            'password_hash': hash_password(data['password']),
            'role': data['role']
        }
        
        result = supabase.from_('users').insert(user_data).execute()
        
        if not result.data:
            return jsonify({'message': 'Erreur création utilisateur'}), 500
        
        new_user = result.data[0]
        
        # Générer le token
        token = generate_token({
            'id': new_user['id'],
            'email': new_user['email'],
            'role': new_user['role']
        })
        
        return jsonify({
            'message': 'Compte créé avec succès',
            'token': token,
            'user': {
                'id': new_user['id'],
                'nom': new_user['nom'],
                'email': new_user['email'],
                'role': new_user['role']
            }
        }), 201
        
    except Exception as e:
        logger.error(f"Erreur registration: {e}")
        return jsonify({'message': 'Erreur interne du serveur'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Connexion utilisateur"""
    try:
        data = request.get_json()
        
        # Validation
        if 'email' not in data or 'password' not in data:
            return jsonify({'message': 'Email et mot de passe requis'}), 400
        
        # Récupérer l'utilisateur
        result = supabase.from_('users').select('*').eq('email', data['email']).execute()
        
        if not result.data:
            return jsonify({'message': 'Email ou mot de passe incorrect'}), 401
        
        user = result.data[0]
        
        # Vérifier le mot de passe
        if not check_password(data['password'], user['password_hash']):
            return jsonify({'message': 'Email ou mot de passe incorrect'}), 401
        
        # Générer le token
        token = generate_token({
            'id': user['id'],
            'email': user['email'],
            'role': user['role']
        })
        
        return jsonify({
            'message': 'Connexion réussie',
            'token': token,
            'user': {
                'id': user['id'],
                'nom': user['nom'],
                'email': user['email'],
                'role': user['role']
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Erreur login: {e}")
        return jsonify({'message': 'Erreur interne du serveur'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@token_required
def logout():
    """Déconnexion"""
    return jsonify({'message': 'Déconnexion réussie'}), 200

@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user():
    """Récupérer les infos de l'utilisateur courant"""
    try:
        user_id = request.user['user_id']
        result = supabase.from_('users').select('id, nom, email, role, created_at').eq('id', user_id).execute()
        
        if not result.data:
            return jsonify({'message': 'Utilisateur non trouvé'}), 404
        
        return jsonify({'user': result.data[0]}), 200
        
    except Exception as e:
        logger.error(f"Erreur get_current_user: {e}")
        return jsonify({'message': 'Erreur interne du serveur'}), 500

# =====================================================
# ROUTES PATIENTS
# =====================================================

@app.route('/api/patients', methods=['GET'])
@token_required
def get_patients():
    """Récupérer tous les patients"""
    try:
        # Selon le rôle, on peut filtrer les patients
        user_role = request.user['role']
        
        query = supabase.from_('patients').select('*').order('created_at', desc=True)
        
        # Si l'utilisateur n'est pas admin ou docteur, limiter l'accès
        if user_role not in ['admin', 'docteur', 'medecin']:
            query = query.limit(50)  # Limiter les résultats pour les autres rôles
        
        result = query.execute()
        
        return jsonify({'patients': result.data}), 200
        
    except Exception as e:
        logger.error(f"Erreur get_patients: {e}")
        return jsonify({'message': 'Erreur interne du serveur'}), 500

@app.route('/api/patients/<patient_id>', methods=['GET'])
@token_required
def get_patient(patient_id):
    """Récupérer un patient spécifique"""
    try:
        result = supabase.from_('patients').select('*').eq('id', patient_id).execute()
        
        if not result.data:
            return jsonify({'message': 'Patient non trouvé'}), 404
        
        return jsonify({'patient': result.data[0]}), 200
        
    except Exception as e:
        logger.error(f"Erreur get_patient: {e}")
        return jsonify({'message': 'Erreur interne du serveur'}), 500

@app.route('/api/patients', methods=['POST'])
@token_required
def create_patient():
    """Créer un nouveau patient"""
    try:
        data = request.get_json()
        
        # Validation
        required_fields = ['nom_complet', 'date_naissance']
        for field in required_fields:
            if field not in data:
                return jsonify({'message': f'Champ {field} manquant'}), 400
        
        # Vérifier les permissions
        user_role = request.user['role']
        if user_role not in ['admin', 'accueil', 'docteur', 'medecin']:
            return jsonify({'message': 'Permission refusée pour créer un patient'}), 403
        
        # Ajouter l'utilisateur qui crée
        patient_data = {
            'nom_complet': data['nom_complet'],
            'date_naissance': data['date_naissance'],
            'telephone': data.get('telephone'),
            'email': data.get('email'),
            'adresse': data.get('adresse'),
            'created_by': request.user['user_id']
        }
        
        result = supabase.from_('patients').insert(patient_data).execute()
        
        if not result.data:
            return jsonify({'message': 'Erreur création patient'}), 500
        
        return jsonify({
            'message': 'Patient créé avec succès',
            'patient': result.data[0]
        }), 201
        
    except Exception as e:
        logger.error(f"Erreur create_patient: {e}")
        return jsonify({'message': 'Erreur interne du serveur'}), 500

@app.route('/api/patients/<patient_id>', methods=['PUT'])
@token_required
def update_patient(patient_id):
    """Mettre à jour un patient"""
    try:
        data = request.get_json()
        
        # Vérifier les permissions
        user_role = request.user['role']
        if user_role not in ['admin', 'docteur', 'medecin']:
            return jsonify({'message': 'Permission refusée pour modifier un patient'}), 403
        
        # Vérifier si le patient existe
        existing = supabase.from_('patients').select('*').eq('id', patient_id).execute()
        if not existing.data:
            return jsonify({'message': 'Patient non trouvé'}), 404
        
        # Préparer les données à mettre à jour
        update_data = {}
        fields = ['nom_complet', 'date_naissance', 'telephone', 'email', 'adresse']
        for field in fields:
            if field in data:
                update_data[field] = data[field]
        
        if not update_data:
            return jsonify({'message': 'Aucune donnée à mettre à jour'}), 400
        
        update_data['updated_at'] = datetime.utcnow().isoformat()
        
        result = supabase.from_('patients').update(update_data).eq('id', patient_id).execute()
        
        return jsonify({
            'message': 'Patient mis à jour avec succès',
            'patient': result.data[0] if result.data else None
        }), 200
        
    except Exception as e:
        logger.error(f"Erreur update_patient: {e}")
        return jsonify({'message': 'Erreur interne du serveur'}), 500

@app.route('/api/patients/<patient_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_patient(patient_id):
    """Supprimer un patient (admin seulement)"""
    try:
        # Vérifier si le patient existe
        existing = supabase.from_('patients').select('*').eq('id', patient_id).execute()
        if not existing.data:
            return jsonify({'message': 'Patient non trouvé'}), 404
        
        # Supprimer le patient
        supabase.from_('patients').delete().eq('id', patient_id).execute()
        
        return jsonify({'message': 'Patient supprimé avec succès'}), 200
        
    except Exception as e:
        logger.error(f"Erreur delete_patient: {e}")
        return jsonify({'message': 'Erreur interne du serveur'}), 500

# =====================================================
# ROUTES UTILISATEURS (ADMIN SEULEMENT)
# =====================================================

@app.route('/api/users', methods=['GET'])
@token_required
@admin_required
def get_users():
    """Récupérer tous les utilisateurs (admin seulement)"""
    try:
        result = supabase.from_('users').select('id, nom, email, role, created_at').order('created_at', desc=True).execute()
        
        return jsonify({'users': result.data}), 200
        
    except Exception as e:
        logger.error(f"Erreur get_users: {e}")
        return jsonify({'message': 'Erreur interne du serveur'}), 500

@app.route('/api/users/<user_id>', methods=['PUT'])
@token_required
@admin_required
def update_user(user_id):
    """Mettre à jour un utilisateur (admin seulement)"""
    try:
        data = request.get_json()
        
        # Empêcher de créer d'autres admins
        if 'role' in data and data['role'] == 'admin':
            return jsonify({'message': 'Création de compte admin non autorisée'}), 403
        
        # Vérifier si l'utilisateur existe
        existing = supabase.from_('users').select('*').eq('id', user_id).execute()
        if not existing.data:
            return jsonify({'message': 'Utilisateur non trouvé'}), 404
        
        # Ne pas permettre de modifier l'admin principal
        if existing.data[0]['email'] == ADMIN_EMAIL:
            return jsonify({'message': 'Modification du compte admin principal non autorisée'}), 403
        
        # Préparer les données à mettre à jour
        update_data = {}
        if 'nom' in data:
            update_data['nom'] = data['nom']
        if 'role' in data:
            update_data['role'] = data['role']
        
        if not update_data:
            return jsonify({'message': 'Aucune donnée à mettre à jour'}), 400
        
        update_data['updated_at'] = datetime.utcnow().isoformat()
        
        result = supabase.from_('users').update(update_data).eq('id', user_id).execute()
        
        return jsonify({
            'message': 'Utilisateur mis à jour avec succès',
            'user': result.data[0] if result.data else None
        }), 200
        
    except Exception as e:
        logger.error(f"Erreur update_user: {e}")
        return jsonify({'message': 'Erreur interne du serveur'}), 500

@app.route('/api/users/<user_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_user(user_id):
    """Supprimer un utilisateur (admin seulement)"""
    try:
        # Vérifier si l'utilisateur existe
        existing = supabase.from_('users').select('*').eq('id', user_id).execute()
        if not existing.data:
            return jsonify({'message': 'Utilisateur non trouvé'}), 404
        
        # Ne pas permettre de supprimer l'admin principal
        if existing.data[0]['email'] == ADMIN_EMAIL:
            return jsonify({'message': 'Suppression du compte admin principal non autorisée'}), 403
        
        # Supprimer l'utilisateur
        supabase.from_('users').delete().eq('id', user_id).execute()
        
        return jsonify({'message': 'Utilisateur supprimé avec succès'}), 200
        
    except Exception as e:
        logger.error(f"Erreur delete_user: {e}")
        return jsonify({'message': 'Erreur interne du serveur'}), 500

# =====================================================
# ROUTES DASHBOARD
# =====================================================

@app.route('/api/dashboard/stats', methods=['GET'])
@token_required
def get_dashboard_stats():
    """Récupérer les statistiques du tableau de bord"""
    try:
        user_role = request.user['role']
        
        stats = {
            'patients_total': 0,
            'patients_today': 0,
            'rendezvous_today': 0,
            'prescriptions_pending': 0
        }
        
        # Compter les patients
        patients_result = supabase.from_('patients').select('id', count='exact').execute()
        if hasattr(patients_result, 'count'):
            stats['patients_total'] = patients_result.count
        
        # Selon le rôle, ajuster les stats
        if user_role == 'admin':
            users_result = supabase.from_('users').select('id', count='exact').execute()
            if hasattr(users_result, 'count'):
                stats['users_total'] = users_result.count
        
        return jsonify({'stats': stats}), 200
        
    except Exception as e:
        logger.error(f"Erreur get_dashboard_stats: {e}")
        return jsonify({'message': 'Erreur interne du serveur'}), 500

# =====================================================
# ROUTES SANTÉ
# =====================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Vérifier la santé de l'API"""
    try:
        # Tester la connexion à Supabase
        supabase.from_('users').select('count', count='exact').limit(1).execute()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'hospital-backend'
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

# =====================================================
# CONFIGURATION ET DÉMARRAGE
# =====================================================

if __name__ == '__main__':
    # Initialiser la base de données
    if init_database():
        logger.info("Backend HospitalApp démarré avec succès")
        app.run(host='0.0.0.0', port=5000, debug=True)
    else:
        logger.error("Échec de l'initialisation de la base de données")

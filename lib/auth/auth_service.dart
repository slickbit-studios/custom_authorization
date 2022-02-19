import 'package:firebase_auth/firebase_auth.dart';

abstract class AuthService {
  Future<UserCredential> signup(String email, String password);
  Future<UserCredential> signInWithCredentials(String email, String password);
  Future<UserCredential?> signInWithGoogle();
  Future<UserCredential?> signInWithFacebook();
  Future<UserCredential?> signInWithApple();
  Future<void> sendEmailVerification();
  Future<void> sendResetPassword(String email);

  Future logout();
  User? get currentUser;
  bool get isVerified;
}

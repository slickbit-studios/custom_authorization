import 'package:firebase_auth/firebase_auth.dart';

abstract class AuthService {
  Future<UserCredential> signup(String email, String password);
  Future<UserCredential> signInAnonymously();
  Future<UserCredential> signInWithCredentials(String email, String password);
  Future<UserCredential?> signInWithGoogle();
  Future<UserCredential?> signInWithFacebook();
  Future<UserCredential?> signInWithApple();
  Future<void> sendEmailVerification();
  Future<void> sendResetPassword(String email);
  Future<void> changeMail(String mail);
  Future<void> changePassword(String password);
  Future<String?> getImageUrl({int size});

  Future logout();
  User? get currentUser;
  bool get signedIn;
  bool get isVerified;
}

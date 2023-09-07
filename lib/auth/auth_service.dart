abstract class AuthData {
  const AuthData();

  String get uid;
  String? get name;
  String? get email;
  bool get emailVerified;
  Future<String?> get token;
  bool get anonymous;
}

abstract class AuthService {
  Future<bool> signup(String email, String password);
  Future<bool> signInAnonymously();
  Future<bool> signInWithCredentials(String email, String password);
  Future<bool> signInWithGoogle({String? clientId});
  Future<bool> signInWithFacebook();
  Future<bool> signInWithApple();
  Future<void>? sendEmailVerification();
  Future<void> sendResetPassword(String email);
  Future<void> changeMail(String mail);
  Future<void> changePassword(String password);
  Future<String?> getImageUrl({int size});
  Future<AuthData?> reloadAuthorization();

  Future<void> logout();
  AuthData? get currentUser;
  bool get signedIn;
  bool get isVerified;
}

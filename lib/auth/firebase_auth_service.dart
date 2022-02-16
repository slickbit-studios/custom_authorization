import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:custom_services/util/logger.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter_facebook_auth/flutter_facebook_auth.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';

import 'auth_exception.dart';
import 'auth_service.dart';

const TAG_PROVIDER = 'providerId';
const PROVIDER_FACEBOOK = 'facebook.com';
const PROVIDER_APPLE = 'apple.com';
const PROVIDER_GOOGLE = 'google.com';
const SOCIAL_PROVIDERS = [PROVIDER_APPLE, PROVIDER_FACEBOOK, PROVIDER_GOOGLE];

class FirebaseAuthService extends AuthService {
  final FirebaseAuth _firebaseAuth;

  FirebaseAuthService() : _firebaseAuth = FirebaseAuth.instance;

  @override
  User? get currentUser => _firebaseAuth.currentUser;

  @override
  Future<UserCredential> signup(String email, String password) async {
    UserCredential? credentials;
    try {
      credentials = await _firebaseAuth.createUserWithEmailAndPassword(
          email: email, password: password);
      credentials.user!.sendEmailVerification();
    } catch (e) {
      throw AuthException.from(e);
    }
    return credentials;
  }

  @override
  Future<UserCredential> signInWithCredentials(
    String email,
    String password,
  ) async {
    UserCredential? credential;
    try {
      credential = await _firebaseAuth.signInWithEmailAndPassword(
        email: email,
        password: password,
      );
    } catch (e) {
      throw AuthException.from(e, method: 'Credentials');
    }
    return credential;
  }

  @override
  Future<UserCredential?> signInWithGoogle() async {
    try {
      final GoogleSignInAccount? user = await GoogleSignIn().signIn();

      if (user != null) {
        final GoogleSignInAuthentication googleAuth = await user.authentication;
        final oAuthCredential = GoogleAuthProvider.credential(
          accessToken: googleAuth.accessToken,
          idToken: googleAuth.idToken,
        );
        return await _firebaseAuth.signInWithCredential(oAuthCredential);
      }
    } on FirebaseAuthException catch (e) {
      throw AuthException.from(e, method: 'Google');
    } catch (e) {
      Logger.instance.error(
        module: 'AuthService',
        message: 'Unknown exception on sign in with google: $e',
      );
      throw AuthException(AuthExceptionType.UNCLASSIFIED);
    }

    return Future.value(null);
  }

  @override
  Future<UserCredential?> signInWithFacebook() async {
    final LoginResult loginResult = await FacebookAuth.instance.login();

    if (loginResult.accessToken != null) {
      final OAuthCredential oAuthCredential =
          FacebookAuthProvider.credential(loginResult.accessToken!.token);

      try {
        return await _firebaseAuth.signInWithCredential(oAuthCredential);
      } catch (e) {
        throw AuthException.from(e, method: 'Facebook');
      }
    }

    return Future.value(null);
  }

  @override
  Future<UserCredential> signInWithApple() async {
    // When signing in, the nonce in the id token returned by Apple is expected
    // to match the sha256 hash of `rawNonce`.
    final rawNonce = _generateNonce();
    final nonce = _sha256ofString(rawNonce);

    try {
      final appleCredential = await SignInWithApple.getAppleIDCredential(
        scopes: [
          AppleIDAuthorizationScopes.email,
          AppleIDAuthorizationScopes.fullName,
        ],
        nonce: nonce,
      );

      final oAuthCredential = OAuthProvider(PROVIDER_APPLE).credential(
        idToken: appleCredential.identityToken,
        rawNonce: rawNonce,
      );

      return await _firebaseAuth.signInWithCredential(oAuthCredential);
    } catch (e) {
      throw AuthException.from(e, method: 'Facebook');
    }
  }

  @override
  Future logout() {
    return _firebaseAuth.signOut();
  }

  /// Generates a cryptographically secure random nonce, to be included in a
  /// credential request.
  String _generateNonce([int length = 32]) {
    const charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVXYZ'
        'abcdefghijklmnopqrstuvwxyz-._';
    final random = Random.secure();
    return List.generate(length, (_) => charset[random.nextInt(charset.length)])
        .join();
  }

  /// Returns the sha256 hash of [input] in hex notation.
  String _sha256ofString(String input) {
    final bytes = utf8.encode(input);
    final digest = sha256.convert(bytes);
    return digest.toString();
  }

  @override
  bool get isVerified {
    var user = currentUser;

    if (user == null) {
      return false;
    } else if (user.emailVerified) {
      return true;
    } else {
      for (var userInfo in user.providerData) {
        if (SOCIAL_PROVIDERS.contains(userInfo.providerId)) {
          return true;
        }
      }
    }

    return false;
  }

  @override
  Future<void> sendEmailVerification() async {
    return _firebaseAuth.currentUser?.sendEmailVerification();
  }
}

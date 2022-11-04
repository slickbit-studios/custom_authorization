import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:custom_services/services/crash_report/logger.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
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

class FirebaseAuthData extends AuthData {
  final User _firebaseUser;

  const FirebaseAuthData._(this._firebaseUser);

  @override
  String? get email => _firebaseUser.email;

  @override
  bool get emailVerified => _firebaseUser.emailVerified;

  @override
  String? get name => _firebaseUser.displayName;

  @override
  String get uid => _firebaseUser.uid;
}

class FirebaseAuthService extends AuthService {
  final FirebaseAuth _firebaseAuth;

  FirebaseAuthService() : _firebaseAuth = FirebaseAuth.instance;

  @override
  AuthData? get currentUser => _firebaseAuth.currentUser == null
      ? null
      : FirebaseAuthData._(_firebaseAuth.currentUser!);

  @override
  Future<bool> signup(String email, String password) async {
    await removeUserIfAnonymous();

    UserCredential? credentials;
    try {
      credentials = await _firebaseAuth.createUserWithEmailAndPassword(
        email: email,
        password: password,
      );
      credentials.user!.sendEmailVerification();
    } catch (e) {
      throw AuthException.from(e);
    }

    return true;
  }

  @override
  Future<bool> signInAnonymously() async {
    try {
      await _firebaseAuth.signInAnonymously();
      return true;
    } catch (e) {
      throw AuthException.from(e);
    }
  }

  @override
  Future<bool> signInWithCredentials(String email, String password) async {
    try {
      await removeUserIfAnonymous();

      await _firebaseAuth.signInWithEmailAndPassword(
        email: email,
        password: password,
      );

      return true;
    } catch (e) {
      throw AuthException.from(e, method: 'Credentials');
    }
  }

  @override
  Future<bool> signInWithGoogle({String? clientId}) async {
    try {
      await removeUserIfAnonymous();

      final GoogleSignInAccount? user =
          await GoogleSignIn(clientId: clientId).signIn();

      if (user == null) {
        return false;
      }

      final GoogleSignInAuthentication googleAuth = await user.authentication;
      final oAuthCredential = GoogleAuthProvider.credential(
        accessToken: googleAuth.accessToken,
        idToken: googleAuth.idToken,
      );

      await _firebaseAuth.signInWithCredential(oAuthCredential);
      return true;
    } on FirebaseAuthException catch (e) {
      throw AuthException.from(e, method: 'Google');
    } on PlatformException catch (_) {
      throw AuthException(AuthExceptionType.PLATFORM_ERROR);
    } catch (e) {
      Logger.error(
        module: runtimeType,
        message: 'Unknown exception on sign in with google: $e',
      );
      throw AuthException(AuthExceptionType.UNCLASSIFIED);
    }
  }

  @override
  Future<bool> signInWithFacebook() async {
    if (kIsWeb) {
      var provider = FacebookAuthProvider();
      provider.addScope('email');
      provider.setCustomParameters({'display': 'popup'});

      try {
        await removeUserIfAnonymous();
        await FirebaseAuth.instance.signInWithPopup(provider);
      } catch (e) {
        throw AuthException.from(e, method: 'Facebook');
      }
    } else {
      final LoginResult loginResult = await FacebookAuth.instance.login();

      if (loginResult.accessToken == null) {
        return false;
      }

      try {
        await removeUserIfAnonymous();

        final OAuthCredential oAuthCredential =
            FacebookAuthProvider.credential(loginResult.accessToken!.token);

        await _firebaseAuth.signInWithCredential(oAuthCredential);
      } catch (e) {
        throw AuthException.from(e, method: 'Facebook');
      }
    }

    return true;
  }

  @override
  Future<bool> signInWithApple() async {
    // When signing in, the nonce in the id token returned by Apple is expected
    // to match the sha256 hash of `rawNonce`.
    final rawNonce = _generateNonce();
    final nonce = _sha256ofString(rawNonce);

    try {
      await removeUserIfAnonymous();

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

      await _firebaseAuth.signInWithCredential(oAuthCredential);
    } catch (e) {
      throw AuthException.from(e, method: 'Apple');
    }

    return true;
  }

  @override
  Future<void> logout({bool removeAnonymous = true}) async {
    // try to rotate firebase cloud messaging token
    try {} catch (err) {
      Logger.warning(
        module: runtimeType,
        message: 'Failed to rotate fcm key: $err',
      );
    }

    // delete anonymous account in firebase
    if (removeAnonymous) {
      await removeUserIfAnonymous();
    }

    // sign out
    if (_firebaseAuth.currentUser != null) {
      await _firebaseAuth.signOut();
    }
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
    var user = _firebaseAuth.currentUser;

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
  Future<void>? sendEmailVerification() =>
      _firebaseAuth.currentUser?.sendEmailVerification();

  @override
  Future<void> sendResetPassword(String email) =>
      _firebaseAuth.sendPasswordResetEmail(email: email);

  @override
  Future<void> changePassword(String password) {
    return _firebaseAuth.currentUser!.updatePassword(password);
  }

  @override
  Future<void> changeMail(String mail) async {
    try {
      await _firebaseAuth.currentUser!.verifyBeforeUpdateEmail(mail);
    } catch (err) {
      throw AuthException.from(err);
    }
  }

  @override
  bool get signedIn => _firebaseAuth.currentUser != null;

  @override
  Future<String?> getImageUrl({int size = 128}) async {
    String? url = _firebaseAuth.currentUser?.photoURL;

    if (url == null) {
      return null;
    }

    // set size
    url += '?width=$size';

    // facebook requires access token in url
    var facebookToken = await FacebookAuth.instance.accessToken;
    if (facebookToken != null) {
      url += "&access_token=${facebookToken.token}";
    }

    return url;
  }

  Future<void> removeUserIfAnonymous() async {
    var user = _firebaseAuth.currentUser;
    if (user?.isAnonymous ?? false) {
      return await _firebaseAuth.currentUser?.delete();
    }
  }

  @override
  Future<AuthData?> reloadAuthorization() async {
    await _firebaseAuth.currentUser?.reload();
    return currentUser;
  }
}

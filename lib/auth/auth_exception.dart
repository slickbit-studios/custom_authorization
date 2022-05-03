import 'package:custom_services/util/logger.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';

enum AuthExceptionType {
  UNCLASSIFIED,
  WEAK_PASSWORD,
  EMAIL_IN_USE,
  USER_NOT_EXISTS,
  PASSWORD_WRONG,
  ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL,
  PLATFORM_ERROR,
  NOT_COMPLETED,
  TOO_MANY_REQUESTS,
  INVALID_CREDENTIAL
}

class AuthException {
  final AuthExceptionType type;

  AuthException(this.type);

  static AuthException from(Object err, {String method = ''}) {
    if (err is FirebaseAuthException) {
      if (err.code == 'weak-password') {
        throw AuthException(AuthExceptionType.WEAK_PASSWORD);
      } else if (err.code == 'email-already-in-use') {
        throw AuthException(AuthExceptionType.EMAIL_IN_USE);
      } else if (err.code == 'user-not-found' ) {
        throw AuthException(AuthExceptionType.USER_NOT_EXISTS);
      } else if ( err.code == 'wrong-password') {
        throw AuthException(AuthExceptionType.PASSWORD_WRONG);
      } else if (err.code == 'too-many-requests') {
        throw AuthException(AuthExceptionType.TOO_MANY_REQUESTS);
      } else if (err.code == 'account-exists-with-different-credential') {
        return AuthException(
          AuthExceptionType.ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL,
        );
      } else if (err.code == 'invalid-credential') {
        return AuthException(AuthExceptionType.INVALID_CREDENTIAL);
      } else {
        Logger.instance.error(
          module: AuthException,
          message: 'Unhandled code on signin with $method: ${err.code}',
        );
        return AuthException(AuthExceptionType.UNCLASSIFIED);
      }
    } else if (err is SignInWithAppleAuthorizationException) {
      throw AuthException(AuthExceptionType.NOT_COMPLETED);
    } else {
      return AuthException(AuthExceptionType.UNCLASSIFIED);
    }
  }
}

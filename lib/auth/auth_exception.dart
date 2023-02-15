import 'package:custom_services/services/crash_report/logger.dart';
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
  INVALID_CREDENTIAL,
  RECENT_LOGIN_REQUIRED,
  REQUEST_ERROR
}

class AuthException {
  final AuthExceptionType type;
  final dynamic error;

  AuthException(this.type, {this.error});

  static AuthException from(Object err, {String method = ''}) {
    if (err is FirebaseAuthException) {
      if (err.code == 'weak-password') {
        return AuthException(AuthExceptionType.WEAK_PASSWORD);
      } else if (err.code == 'email-already-in-use') {
        return AuthException(AuthExceptionType.EMAIL_IN_USE);
      } else if (err.code == 'user-not-found') {
        return AuthException(AuthExceptionType.USER_NOT_EXISTS);
      } else if (err.code == 'wrong-password') {
        return AuthException(AuthExceptionType.PASSWORD_WRONG);
      } else if (err.code == 'too-many-requests') {
        return AuthException(AuthExceptionType.TOO_MANY_REQUESTS);
      } else if (err.code == 'account-exists-with-different-credential') {
        return AuthException(
          AuthExceptionType.ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL,
        );
      } else if (err.code == 'invalid-credential') {
        return AuthException(AuthExceptionType.INVALID_CREDENTIAL);
      } else if (err.code == 'popup-closed-by-user') {
        return AuthException(AuthExceptionType.NOT_COMPLETED);
      } else if (err.code == 'requires-recent-login') {
        return AuthException(AuthExceptionType.RECENT_LOGIN_REQUIRED);
      } else if (err.code == 'network-request-failed') {
        return AuthException(AuthExceptionType.REQUEST_ERROR);
      } else {
        Logger.error(
          module: AuthException,
          message: 'Unhandled code on signin with $method: ${err.code}',
        );

        return AuthException(AuthExceptionType.UNCLASSIFIED, error: err);
      }
    } else if (err is SignInWithAppleAuthorizationException) {
      return AuthException(AuthExceptionType.NOT_COMPLETED);
    } else {
      Logger.error(
        module: AuthException,
        message: 'Unexpected error on signin with $method: $err',
      );

      return AuthException(AuthExceptionType.UNCLASSIFIED, error: err);
    }
  }

  @override
  String toString() {
    String result = type.name;
    if (error != null) {
      result += ': $error';
    }
    return result;
  }
}

import 'dart:typed_data';

import 'package:bip39/bip39.dart' as bip39;

import 'package:aleo_dart/src/utils.dart';
import 'package:aleo_dart/src/rust_lib/rust_ffi.dart';
import 'package:aleo_dart/src/aleo_hd_key.dart';

const ALEO_PATH = "m/44/0/0/0";

Uint8List mnemonicToSeed(String mnemonic) {
  final rootSeed = bip39.mnemonicToSeed(mnemonic);
  return derive(ALEO_PATH, rootSeed);
}

String seedToPrivateKey(Uint8List seedRaw) {
  final seed = dartListToC(seedRaw);
  final privateKey = RustFFI.seedToPrivateKey(seed);
  return cStrToDart(privateKey);
}

String privateKeyToAddress(String privateKeyRaw) {
  final privateKey = dartStrToC(privateKeyRaw);
  final address = RustFFI.privateKeyToAddress(privateKey);
  return cStrToDart(address);
}

String privateKeyToViewKey(String privateKeyRaw) {
  final privateKey = dartStrToC(privateKeyRaw);
  final viewKey = RustFFI.privateKeyToViewKey(privateKey);
  return cStrToDart(viewKey);
}

String viewKeyToAddress(String viewKeyRaw) {
  final viewKey = dartStrToC(viewKeyRaw);
  final address = RustFFI.viewKeyToAddress(viewKey);
  return cStrToDart(address);
}

String sign(String privateKeyRaw, Uint8List messageRaw) {
  final privateKey = dartStrToC(privateKeyRaw);
  final message = dartListToC(messageRaw);
  final signature = RustFFI.sign(privateKey, message, messageRaw.length);
  return cStrToDart(signature);
}

bool isValidSignature(
    String addressRaw, String signatureRaw, Uint8List messageRaw) {
  final address = dartStrToC(addressRaw);
  final signature = dartStrToC(signatureRaw);
  final message = dartListToC(messageRaw);
  return RustFFI.isValidSignature(
      address, signature, message, messageRaw.length);
}

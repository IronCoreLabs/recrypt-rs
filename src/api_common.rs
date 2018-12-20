//quick_error! {
//    /// Errors generated by the API
//    #[derive(Debug, PartialEq)]
//    pub enum ApiErr {
//        DecryptFailed(err: internal::InternalError){
//            display("The decryption failed. Ensure you're using the correct PrivateKey.")
//            cause(err)
//        }
//        InvalidEncryptedMessageSignature(err: internal::InternalError){
//            display("The signature of the encrypted value could not be verified.")
//            cause(err)
//        }
//        InvalidPublicKey(err: internal::homogeneouspoint::PointErr){
//            display("The public key was not valid. Ensure it was generated from a valid PrivateKey.")
//            from()
//            cause(err)
//        }
//        InvalidTransformKey(err: internal::InternalError){
//            cause(err)
//            display("The transform key signature was incorrect.")
//        }
//        InputWrongSize(typ: &'static str, req_size: usize){
//            display("The input value was the wrong size. Expected {} bytes for type {}.", req_size, typ)
//        }
//        DecodeFailure(err: internal::bytedecoder::DecodeErr){
//            display("The bytes could not be decoded into the appropriate data type.")
//            cause(err)
//            from()
//        }
//    }
//}
//
//type Result<T> = std::result::Result<T, ApiErr>;
//
//impl From<internal::InternalError> for ApiErr {
//    fn from(err: internal::InternalError) -> Self {
//        match err {
//            internal::InternalError::AuthHashMatchFailed => ApiErr::DecryptFailed(err),
//            internal::InternalError::InvalidEncryptedMessageSignature => {
//                ApiErr::InvalidEncryptedMessageSignature(err)
//            }
//            internal::InternalError::PointInvalid(p_err) => ApiErr::InvalidPublicKey(p_err),
//            internal::InternalError::CorruptReencryptionKey => ApiErr::InvalidTransformKey(err),
//        }
//    }
//}
class CipherState(object):
    @property
    def cipher(self):
        return None

    def initialize_key(self, key):
        """
        Sets k = key. Sets n = 0.

        :param key:
        :type key:
        :return:
        :rtype:
        """

    def has_key(self):
        """
        :return: true if k is non-empty, false otherwise
        :rtype: bool
        """

    def set_nonce(self, nonce):
        """
        SetNonce(nonce): Sets n = nonce.
        This function is used for handling out-of-order transport messages

        :param nonce:
        :type nonce: int
        :return:
        :rtype:
        """

    def rekey(self):
        """
        Sets k = REKEY(k)

        :return:
        :rtype:
        """

    def encrypt_with_ad(self, ad, plaintext):
        """
        EncryptWithAd(ad, plaintext):
        If k is non-empty returns ENCRYPT(k, n++, ad, plaintext). Otherwise returns plaintext.

        :param ad:
        :type ad: bytes
        :param plaintext:
        :type plaintext: bytes
        :return:
        :rtype: bytes
        """

    def decrypt_with_ad(self, ad, ciphertext):
        """
        DecryptWithAd(ad, ciphertext):
        If k is non-empty returns DECRYPT(k, n++, ad, ciphertext). Otherwise returns ciphertext.
        If an authentication failure occurs in DECRYPT() then n is not incremented
        and an error is signaled to the caller.

        :param ad:
        :type ad: bytes
        :param ciphertext:
        :type ciphertext: bytes
        :return: bytes
        :rtype:
        """

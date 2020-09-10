class Vault:

    @staticmethod
    def setSomething(something):
        Vault.__something = something

    @staticmethod
    def getSomething():
        return Vault.__something

import unittest


class MyTest(unittest.TestCase):
    def test_method1(self):
        print('test')
        assert 1  # fail for demo purposes

    def test_method2(self):
        assert 1  # fail for demo purposes

if __name__ == '__main__':
    unittest.main()

import unittest

import server


class NodeOrderTests(unittest.TestCase):
    def setUp(self):
        self.nodes = [{"name": name} for name in ("A", "B", "C", "D")]

    def names(self):
        return [node["name"] for node in self.nodes]

    def test_move_with_buttons(self):
        self.assertTrue(server.reorder_nodes(self.nodes, {"name": "C", "direction": -1}))
        self.assertEqual(self.names(), ["A", "C", "B", "D"])
        self.assertTrue(server.reorder_nodes(self.nodes, {"name": "C", "direction": 1}))
        self.assertEqual(self.names(), ["A", "B", "C", "D"])

    def test_drag_before_and_after(self):
        self.assertTrue(server.reorder_nodes(self.nodes, {"name": "D", "targetName": "B", "position": "before"}))
        self.assertEqual(self.names(), ["A", "D", "B", "C"])
        self.assertTrue(server.reorder_nodes(self.nodes, {"name": "A", "targetName": "C", "position": "after"}))
        self.assertEqual(self.names(), ["D", "B", "C", "A"])

    def test_boundaries_and_invalid_target(self):
        self.assertFalse(server.reorder_nodes(self.nodes, {"name": "A", "direction": -1}))
        self.assertEqual(self.names(), ["A", "B", "C", "D"])
        with self.assertRaisesRegex(ValueError, "目标节点不存在"):
            server.reorder_nodes(self.nodes, {"name": "B", "targetName": "missing"})
        self.assertEqual(self.names(), ["A", "B", "C", "D"])


if __name__ == "__main__":
    unittest.main()

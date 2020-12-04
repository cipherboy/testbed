import cmsh

import math
import random

def generate_graph(vertices: int, edges: int) -> dict:
    graph = {}
    for vertex in range(vertices):
        graph[vertex] = set()

    assert edges > vertices

    num_edges = 0
    for left in range(vertices):
        right = left
        while right == left:
            right = random.randint(0, vertices - 1)

        assert left != right

        graph[left].add(right)
        graph[right].add(left)
        num_edges += 1

    while num_edges < edges:
        left = random.randint(0, vertices - 1)
        right = left
        while right == left:
            right = random.randint(0, vertices - 1)

        assert left != right

        graph[left].add(right)
        graph[right].add(left)
        num_edges += 1

    return graph

@cmsh.with_model
def num_colors(model, graph, colors):
    bit_size = min(math.ceil(math.log(colors, 2)), 2)

    vertices = {}
    for vertex in graph:
        vertices[vertex] = model.vec(bit_size)
        model.add_assert(vertices[vertex] < colors)

    for left in graph:
        for right in graph[left]:
            assert left != right
            if left < right:
                model.add_assert(vertices[left] != vertices[right])

    if model.solve():
        result = {}
        for vertex in vertices:
            result[vertex] = int(vertices[vertex])

        return result

    return None

def main():
    vertices = 100
    degree = 3
    num_edges = (degree * vertices)//2
    graph = generate_graph(vertices, num_edges)

    result = num_colors(graph, 3)
    print(result)

if __name__ == "__main__":
    main()

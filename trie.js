class TrieNode {
    constructor() {
        this.children = {}; // creates a node of hte { a: trieNode, b: trieNode }
        this.isEndOfWord = false;
    }
}

/**
 *  to use this refrence this 
 * const trie = new Trie();
["watch", "watching", "water", "walker", "wall", "wonder", "app", "apply", "by", "bye"].forEach(word => trie.insert(word));
console.log(trie.suggest(''))
 */

class Trie {
    constructor() {
        this.root = new TrieNode()
    }

    /** this create a prefix with node root like 
     * (root)
    ├── a
    │   └── p
    │        └── p (isEndOfWord = true)
    │             └── l
    │                  └── y (isEndOfWord = true)
    ├── b
        └── y (isEndOfWord = true)
            └── e (isEndOfWord = true)
     * 
     * @param {*} word 
     */

    insert(word) {
        let node = this.root;
        for (let char of word) {
            if (!node.children[char]) node.children[char] = new TrieNode();
            node = node.children[char]
        }
        node.isEndOfWord = true
    }

    // sercarchprefix
    searchPrefix(prefix) {
        let node = this.root;
        for (let char of prefix) {
            if (!node.children[char]) return null;
            node = node.children[char]
        }
        return node;
    }

    suggest(prefix) {
        const results = [];
        const node = this.searchPrefix(prefix);
        if (!node) return results;

        const dfs = (current, path) => {
            if (current.isEndOfWord) results.push(path);
            for (let char in current.children) {
                dfs(current.children[char], path + char);
            }
        };

        dfs(node, prefix);
        return results;
    }

}
module.exports = Trie


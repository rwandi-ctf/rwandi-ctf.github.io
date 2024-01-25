const { htmlTag } = require('hexo-util');

const people = {
    tomato: {
        image: "https://cdn.discordapp.com/avatars/234312273605296129/51ebdaadb65f279337ce85dd19df6c54.png",
    },
    foo: {
        image: "https://cdn.discordapp.com/avatars/345425473213562900/df6e21c85383702b7ca78035bcc1d648.png",
    },
    hartmannsyg: {
        image: "https://cdn.discordapp.com/avatars/1154815737341419530/aef375fa106b8c556ffd0aaa79d7ac5d.png",
    },
    fs: {
        image: "https://cdn.discordapp.com/avatars/933347118402392085/8fe2122c336a05b67a364ef95569685c.png",
    },
    treeindustry: {
        image: "https://cdn.discordapp.com/avatars/637581035227447296/84fe734b031efc508797991d7642d295.png",
    },
    squiddy: {
        image: "https://cdn.discordapp.com/avatars/412969691276115968/1f31f1a29a6334d32dea12924d059416.png",
    }
}

hexo.extend.tag.register('person', function (args, content) {
    const name = args[0]
    const person = people[name]
    if (!person) return htmlTag("div", {}, `unknown person ${name}`, false);
    const img = htmlTag("img", { class: "inline-image rounded-full", width: 30, height: 30, src: person.image }, ' ')
    const link = htmlTag("a", { href: `/tags/author-${name}/` }, name, false)
    return htmlTag("span", {}, img + link, false);
})
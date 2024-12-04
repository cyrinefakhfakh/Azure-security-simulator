# Code Citations

## License: unknown
https://github.com/ReenyDavidson/microblog/tree/abf76a5bcecb60ea3d0e50ab5139d74dd3a095df/app.py

```
)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['
```


## License: BSD_2_Clause
https://github.com/xrlin/SimpleFlaskBlog/tree/58c8943a92a5040b80e0ec7ef098f610bdfe32aa/application/models.py

```
Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db
```


## License: unknown
https://github.com/edgardeng/edgardeng.github.io/tree/5f88f4f1a5205b3b53cb94d366cbe25adf3260e0/article/python/ext_flask_login.md

```
(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120)
```


## License: unknown
https://github.com/tinybike/SuperModular/tree/c9905dcdb52ef944ee20555adaea737a0585396d/dyffy/routes.py

```
)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['
```


## License: CC0_1_0
https://github.com/FadeHack/Ai-Business-Services/tree/36734c73a7a7580eaf391ea9b2f98143208ac69a/app.py

```
'login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email =
```


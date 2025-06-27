from flask import Blueprint, render_template
from auth import login_required
from db import get_user_pending_assignments as read_get_user_pending_assignments, attest_assignment as write_attest_assignment, get_assignment as read_get_assignment, get_policy as read_get_policy
from flask import session, request, redirect, url_for
user = Blueprint('user', __name__, url_prefix='/user')

from time import time

@user.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    user_pending_assignments = read_get_user_pending_assignments(session['user']['uuid'])
    return render_template('user/dashboard.html', 
                         user_pending_assignments=user_pending_assignments["data"],
                         now=int(time()))

@user.route('/attest/<assignment_uuid>', methods=['GET', 'POST'])
@login_required
def attest(assignment_uuid):
    if request.method == 'POST':
        write_attest_assignment(assignment_uuid)
        return redirect(url_for('user.dashboard'))
    assignment = read_get_assignment(uuid=assignment_uuid)
    policy = read_get_policy(uuid=assignment["data"]["policy"])
    return render_template('user/attest.html', assignment_uuid=assignment_uuid, policy=policy)